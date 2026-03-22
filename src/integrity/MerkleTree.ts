/**
 * ============================================================================
 * MERKLE TREE - ДЕРЕВО МЕРКЛА ДЛЯ ВЕРИФИКАЦИИ ЦЕЛОСТНОСТИ
 * ============================================================================
 * Реализация дерева Меркла для эффективной верификации целостности файлов.
 * Позволяет доказывать принадлежность файла к набору без хранения всех хешей.
 * 
 * Особенности:
 * - Поддержка различных алгоритмов хеширования (SHA-256, SHA-512, BLAKE3)
 * - Генерация Merkle proofs для верификации отдельных файлов
 * - Эффективное обновление при изменении листов
 * - Tamper-evident структура
 */

import * as crypto from 'crypto';
import {
  MerkleNode,
  MerkleProof,
  MerkleLeafData,
  MerkleVerificationResult,
  HashAlgorithm,
  FileHash,
  OperationResult
} from '../types/integrity.types';

/**
 * Класс дерева Меркла
 * 
 * Дерево Меркла - это бинарное дерево, где каждый лист содержит хеш файла,
 * а каждый внутренний узел содержит хеш от конкатенации хешей потомков.
 * Корень дерева представляет собой единый хеш, представляющий весь набор данных.
 */
export class MerkleTree {
  /** Корневой узел дерева */
  private root: MerkleNode | null = null;
  
  /** Листовые узлы (файлы) */
  private leaves: MerkleNode[] = [];
  
  /** Алгоритм хеширования */
  private readonly algorithm: HashAlgorithm;
  
  /** Карта путей к индексам листьев */
  private readonly pathToIndex: Map<string, number> = new Map();
  
  /** Все узлы дерева (для сериализации) */
  private allNodes: MerkleNode[] = [];

  /**
   * Создает новый экземпляр MerkleTree
   * 
   * @param algorithm - Алгоритм хеширования (по умолчанию SHA-256)
   */
  constructor(algorithm: HashAlgorithm = 'SHA-256') {
    this.algorithm = algorithm;
  }

  /**
   * Вычисляет хеш данных с использованием настроенного алгоритма
   * 
   * @param data - Данные для хеширования (строка или Buffer)
   * @returns Hex представление хеша
   */
  private hash(data: string | Buffer): string {
    const hash = crypto.createHash(this.getCryptoAlgorithm());
    hash.update(typeof data === 'string' ? Buffer.from(data, 'utf-8') : data);
    return hash.digest('hex');
  }

  /**
   * Преобразует название алгоритма в формат Node.js crypto
   * 
   * @returns Название алгоритма для crypto.createHash
   */
  private getCryptoAlgorithm(): string {
    const algorithmMap: Record<HashAlgorithm, string> = {
      'SHA-256': 'sha256',
      'SHA-384': 'sha384',
      'SHA-512': 'sha512',
      'SHA3-256': 'sha3-256',
      'SHA3-512': 'sha3-512',
      'BLAKE2b': 'blake2b512',
      'BLAKE3': 'blake3' // Требуется установка blake3 пакета
    };
    
    const algo = algorithmMap[this.algorithm];
    if (!algo) {
      throw new Error(`Неподдерживаемый алгоритм хеширования: ${this.algorithm}`);
    }
    
    // BLAKE3 требует отдельной установки
    if (this.algorithm === 'BLAKE3') {
      try {
        // Проверяем доступность BLAKE3
        crypto.createHash('blake3');
        return 'blake3';
      } catch {
        // Fallback на SHA-256 если BLAKE3 недоступен
        console.warn('BLAKE3 недоступен, используем SHA-256');
        return 'sha256';
      }
    }
    
    return algo;
  }

  /**
   * Строит дерево Меркла из массива файлов
   * 
   * @param files - Массив файлов с хешами
   * @returns Корневой хеш дерева
   */
  build(files: FileHash[]): string {
    if (files.length === 0) {
      throw new Error('Невозможно построить дерево из пустого набора файлов');
    }

    // Очищаем предыдущее дерево
    this.leaves = [];
    this.pathToIndex.clear();
    this.allNodes = [];
    this.root = null;

    // Создаем листовые узлы
    const leafNodes: MerkleNode[] = files.map((file, index) => {
      const leafData: MerkleLeafData = {
        filePath: file.filePath,
        fileHash: file.hash,
        index
      };

      const leaf: MerkleNode = {
        hash: this.hashLeaf(file.hash, index),
        data: leafData,
        height: 0
      };

      this.leaves.push(leaf);
      this.pathToIndex.set(file.filePath, index);
      this.allNodes.push(leaf);

      return leaf;
    });

    // Строим дерево рекурсивно
    this.root = this.buildTree(leafNodes);

    return this.root.hash;
  }

  /**
   * Вычисляет хеш листового узла с индексом
   * 
   * @param fileHash - Хеш файла
   * @param index - Индекс листа
   * @returns Хеш листового узла
   */
  private hashLeaf(fileHash: string, index: number): string {
    // Префикс 0x00 для листовых узлов (защита от атак второго прообраза)
    return this.hash(Buffer.concat([
      Buffer.from([0x00]),
      Buffer.from(fileHash, 'hex'),
      Buffer.from([index])
    ]));
  }

  /**
   * Вычисляет хеш внутреннего узла
   * 
   * @param leftHash - Хеш левого потомка
   * @param rightHash - Хеш правого потомка
   * @returns Хеш внутреннего узла
   */
  private hashNode(leftHash: string, rightHash: string): string {
    // Префикс 0x01 для внутренних узлов (защита от атак второго прообраза)
    return this.hash(Buffer.concat([
      Buffer.from([0x01]),
      Buffer.from(leftHash, 'hex'),
      Buffer.from(rightHash, 'hex')
    ]));
  }

  /**
   * Рекурсивно строит дерево из уровня узлов
   * 
   * @param nodes - Узлы текущего уровня
   * @returns Корневой узел поддерева
   */
  private buildTree(nodes: MerkleNode[]): MerkleNode {
    // Базовый случай: один узел
    if (nodes.length === 1) {
      return nodes[0];
    }

    // Если нечетное количество узлов, дублируем последний
    if (nodes.length % 2 !== 0) {
      nodes = [...nodes, { ...nodes[nodes.length - 1] }];
    }

    // Создаем родительский уровень
    const parentNodes: MerkleNode[] = [];
    const height = nodes[0].height + 1;

    for (let i = 0; i < nodes.length; i += 2) {
      const left = nodes[i];
      const right = nodes[i + 1];

      const parentHash = this.hashNode(left.hash, right.hash);

      const parent: MerkleNode = {
        hash: parentHash,
        left,
        right,
        height
      };

      parentNodes.push(parent);
      this.allNodes.push(parent);
    }

    // Рекурсивно строим следующий уровень
    return this.buildTree(parentNodes);
  }

  /**
   * Генерирует Merkle proof для файла
   * 
   * Merkle proof позволяет верифицировать принадлежность файла к дереву
   * без передачи всего дерева. Proof содержит путь от листа до корня
   * с соседними хешами на каждом уровне.
   * 
   * @param filePath - Путь к файлу
   * @returns Merkle proof или null если файл не найден
   */
  generateProof(filePath: string): MerkleProof | null {
    const index = this.pathToIndex.get(filePath);
    
    if (index === undefined || !this.root) {
      return null;
    }

    const leaf = this.leaves[index];
    const siblings: { hash: string; position: 'left' | 'right' }[] = [];
    const path: number[] = [index];

    // Проходим от листа к корню
    let currentIndex = index;
    let currentLevelNodes = this.leaves;

    while (currentLevelNodes.length > 1) {
      // Определяем позицию текущего узла
      const isLeft = currentIndex % 2 === 0;
      const siblingIndex = isLeft ? currentIndex + 1 : currentIndex - 1;

      // Получаем хеш соседа
      if (siblingIndex < currentLevelNodes.length) {
        const sibling = currentLevelNodes[siblingIndex];
        siblings.push({
          hash: sibling.hash,
          position: isLeft ? 'right' : 'left'
        });
      } else {
        // Если соседа нет (нечетное количество), используем тот же узел
        siblings.push({
          hash: currentLevelNodes[currentIndex].hash,
          position: 'right'
        });
      }

      // Переходим на следующий уровень
      currentIndex = Math.floor(currentIndex / 2);
      currentLevelNodes = this.getLevelNodes(currentLevelNodes);
      path.push(currentIndex);
    }

    return {
      leaf: leaf.hash,
      path,
      siblings,
      root: this.root.hash
    };
  }

  /**
   * Получает узлы следующего уровня
   * 
   * @param nodes - Узлы текущего уровня
   * @returns Узлы родительского уровня
   */
  private getLevelNodes(nodes: MerkleNode[]): MerkleNode[] {
    if (nodes.length === 1) {
      return nodes;
    }

    if (nodes.length % 2 !== 0) {
      nodes = [...nodes, { ...nodes[nodes.length - 1] }];
    }

    const parents: MerkleNode[] = [];
    for (let i = 0; i < nodes.length; i += 2) {
      const parent: MerkleNode = {
        hash: this.hashNode(nodes[i].hash, nodes[i + 1].hash),
        left: nodes[i],
        right: nodes[i + 1],
        height: nodes[i].height + 1
      };
      parents.push(parent);
    }

    return parents;
  }

  /**
   * Верифицирует Merkle proof
   * 
   * @param proof - Merkle proof для верификации
   * @returns Результат верификации
   */
  verifyProof(proof: MerkleProof): MerkleVerificationResult {
    const errors: string[] = [];

    try {
      // Вычисляем корень из proof
      let currentHash = proof.leaf;

      for (const sibling of proof.siblings) {
        if (sibling.position === 'left') {
          currentHash = this.hashNode(sibling.hash, currentHash);
        } else {
          currentHash = this.hashNode(currentHash, sibling.hash);
        }
      }

      const computedRoot = currentHash;
      const verified = computedRoot === proof.root;

      if (!verified) {
        errors.push(`Корневой хеш не совпадает: вычислен ${computedRoot}, ожидается ${proof.root}`);
      }

      return {
        verified,
        computedRoot,
        expectedRoot: proof.root,
        errors
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Неизвестная ошибка';
      errors.push(`Ошибка верификации: ${errorMessage}`);
      
      return {
        verified: false,
        computedRoot: '',
        expectedRoot: proof.root,
        errors
      };
    }
  }

  /**
   * Верифицирует файл в дереве
   * 
   * @param filePath - Путь к файлу
   * @param fileHash - Ожидаемый хеш файла
   * @returns Результат верификации
   */
  verifyFile(filePath: string, fileHash: string): MerkleVerificationResult {
    const proof = this.generateProof(filePath);
    
    if (!proof) {
      return {
        verified: false,
        computedRoot: '',
        expectedRoot: this.root?.hash || '',
        errors: [`Файл не найден в дереве: ${filePath}`]
      };
    }

    // Вычисляем хеш листа из fileHash
    const index = this.pathToIndex.get(filePath)!;
    const expectedLeafHash = this.hashLeaf(fileHash, index);

    if (proof.leaf !== expectedLeafHash) {
      return {
        verified: false,
        computedRoot: '',
        expectedRoot: proof.root,
        errors: [`Хеш файла не совпадает с хешем в дереве`]
      };
    }

    return this.verifyProof(proof);
  }

  /**
   * Обновляет хеш файла в дереве
   * 
   * @param filePath - Путь к файлу
   * @param newHash - Новый хеш файла
   * @returns Новый корневой хеш или null если файл не найден
   */
  updateFile(filePath: string, newHash: string): string | null {
    const index = this.pathToIndex.get(filePath);
    
    if (index === undefined || !this.root) {
      return null;
    }

    // Обновляем лист
    const leaf = this.leaves[index];
    leaf.hash = this.hashLeaf(newHash, index);
    if (leaf.data) {
      leaf.data.fileHash = newHash;
    }

    // Перестраиваем путь к корню
    this.rebuildPathToRoot(index);

    return this.root.hash;
  }

  /**
   * Перестраивает путь от листа к корню
   * 
   * @param leafIndex - Индекс листа
   */
  private rebuildPathToRoot(leafIndex: number): void {
    let currentIndex = leafIndex;
    let currentLevel = this.leaves;

    while (currentLevel.length > 1) {
      const parentIndex = Math.floor(currentIndex / 2);
      const isLeft = currentIndex % 2 === 0;
      const siblingIndex = isLeft ? currentIndex + 1 : currentIndex - 1;

      // Получаем узлы для вычисления нового хеша родителя
      const leftNode = isLeft ? currentLevel[currentIndex] : (siblingIndex < currentLevel.length ? currentLevel[siblingIndex] : currentLevel[currentIndex]);
      const rightNode = isLeft ? (siblingIndex < currentLevel.length ? currentLevel[siblingIndex] : currentLevel[currentIndex]) : currentLevel[currentIndex];

      // Находим родительский узел в allNodes и обновляем его хеш
      const parentHash = this.hashNode(leftNode.hash, rightNode.hash);
      
      // Обновляем узел на следующем уровне
      currentIndex = parentIndex;
      currentLevel = this.getLevelNodes(currentLevel);
      
      const parentNode = currentLevel[parentIndex];
      if (parentNode) {
        parentNode.hash = parentHash;
      }
    }
  }

  /**
   * Добавляет новый файл в дерево
   * 
   * @param file - Файл для добавления
   * @returns Новый корневой хеш
   */
  addFile(file: FileHash): string {
    const newFileHash: FileHash = {
      ...file,
      hashedAt: new Date()
    };

    // Создаем новый лист
    const newIndex = this.leaves.length;
    const leafData: MerkleLeafData = {
      filePath: file.filePath,
      fileHash: file.hash,
      index: newIndex
    };

    const leaf: MerkleNode = {
      hash: this.hashLeaf(file.hash, newIndex),
      data: leafData,
      height: 0
    };

    this.leaves.push(leaf);
    this.pathToIndex.set(file.filePath, newIndex);
    this.allNodes.push(leaf);

    // Перестраиваем дерево
    this.root = this.buildTree([...this.leaves]);

    return this.root.hash;
  }

  /**
   * Удаляет файл из дерева
   * 
   * @param filePath - Путь к файлу
   * @returns Новый корневой хеш или null если файл не найден
   */
  removeFile(filePath: string): string | null {
    const index = this.pathToIndex.get(filePath);
    
    if (index === undefined || !this.root) {
      return null;
    }

    // Удаляем лист
    this.leaves.splice(index, 1);

    // Обновляем индексы оставшихся листьев
    this.pathToIndex.clear();
    this.leaves.forEach((leaf, newIndex) => {
      if (leaf.data) {
        leaf.data.index = newIndex;
        leaf.hash = this.hashLeaf(leaf.data.fileHash, newIndex);
      }
      this.pathToIndex.set(leaf.data!.filePath, newIndex);
    });

    // Перестраиваем дерево
    if (this.leaves.length === 0) {
      this.root = null;
      return '';
    }

    this.root = this.buildTree([...this.leaves]);

    return this.root.hash;
  }

  /**
   * Получает корневой хеш
   * 
   * @returns Корневой хеш или null
   */
  getRootHash(): string | null {
    return this.root?.hash || null;
  }

  /**
   * Получает количество листьев
   * 
   * @returns Количество файлов в дереве
   */
  getLeafCount(): number {
    return this.leaves.length;
  }

  /**
   * Получает высоту дерева
   * 
   * @returns Высота дерева
   */
  getHeight(): number {
    return this.root?.height || 0;
  }

  /**
   * Сериализует дерево в JSON
   * 
   * @returns JSON представление дерева
   */
  toJSON(): Record<string, unknown> {
    return {
      algorithm: this.algorithm,
      rootHash: this.root?.hash || null,
      leafCount: this.leaves.length,
      height: this.getHeight(),
      leaves: this.leaves.map(leaf => ({
        hash: leaf.hash,
        data: leaf.data
      })),
      allNodes: this.serializeNodes(this.root)
    };
  }

  /**
   * Сериализует узлы дерева
   * 
   * @param node - Корневой узел
   * @returns Массив сериализованных узлов
   */
  private serializeNodes(node: MerkleNode | null): Record<string, unknown>[] {
    if (!node) {
      return [];
    }

    const result: Record<string, unknown>[] = [{
      hash: node.hash,
      height: node.height,
      data: node.data || null
    }];

    if (node.left) {
      result.push(...this.serializeNodes(node.left));
    }
    if (node.right) {
      result.push(...this.serializeNodes(node.right));
    }

    return result;
  }

  /**
   * Десериализует дерево из JSON
   * 
   * @param data - JSON данные
   * @returns Экземпляр MerkleTree
   */
  static fromJSON(data: Record<string, unknown>): MerkleTree {
    const tree = new MerkleTree(data.algorithm as HashAlgorithm || 'SHA-256');
    
    // Восстанавливаем листья
    const leaves = data.leaves as Array<{ hash: string; data: MerkleLeafData }>;
    tree.leaves = leaves.map(leaf => ({
      hash: leaf.hash,
      data: leaf.data,
      height: 0
    }));

    // Восстанавливаем карту путей
    tree.pathToIndex.clear();
    tree.leaves.forEach((leaf, index) => {
      if (leaf.data) {
        tree.pathToIndex.set(leaf.data.filePath, index);
      }
    });

    // Восстанавливаем корень
    const allNodes = data.allNodes as Record<string, unknown>[] || [];
    if (allNodes.length > 0) {
      tree.root = tree.deserializeNodes(allNodes);
    }

    tree.allNodes = tree.leaves.concat(tree.root ? [tree.root] : []);

    return tree;
  }

  /**
   * Десериализует узлы дерева
   * 
   * @param nodes - Массив узлов
   * @returns Корневой узел
   */
  private deserializeNodes(nodes: Record<string, unknown>[]): MerkleNode | null {
    if (nodes.length === 0) {
      return null;
    }

    // Находим корень (узел с максимальной высотой)
    const rootData = nodes.reduce((max, node) => {
      const height = node.height as number;
      return height > (max.height as number) ? node : max;
    });

    return this.buildNode(rootData, nodes);
  }

  /**
   * Строит узел из данных
   * 
   * @param nodeData - Данные узла
   * @param allNodes - Все узлы
   * @returns Узел дерева
   */
  private buildNode(
    nodeData: Record<string, unknown>,
    allNodes: Record<string, unknown>[]
  ): MerkleNode {
    const node: MerkleNode = {
      hash: nodeData.hash as string,
      height: nodeData.height as number,
      data: nodeData.data as MerkleLeafData | undefined
    };

    // Ищем потомков
    const children = allNodes.filter(n => {
      // Простая эвристика: потомки имеют меньшую высоту
      return (n.height as number) === (nodeData.height as number) - 1;
    });

    if (children.length >= 2) {
      node.left = this.buildNode(children[0], allNodes);
      node.right = this.buildNode(children[1], allNodes);
    }

    return node;
  }

  /**
   * Вычисляет хеш для произвольных данных
   * 
   * @param data - Данные для хеширования
   * @returns Hex хеш
   */
  static hashData(data: string | Buffer, algorithm: HashAlgorithm = 'SHA-256'): string {
    const tree = new MerkleTree(algorithm);
    return tree.hash(data);
  }

  /**
   * Создает дерево из хешей
   * 
   * @param hashes - Массив хешей
   * @param algorithm - Алгоритм хеширования
   * @returns MerkleTree с корневым хешем
   */
  static fromHashes(
    hashes: string[],
    algorithm: HashAlgorithm = 'SHA-256'
  ): { tree: MerkleTree; rootHash: string } {
    const tree = new MerkleTree(algorithm);
    
    // Создаем фиктивные FileHash объекты
    const files: FileHash[] = hashes.map((hash, index) => ({
      filePath: `file_${index}`,
      algorithm,
      hash,
      size: 0,
      mtime: new Date(),
      hashedAt: new Date()
    }));

    const rootHash = tree.build(files);

    return { tree, rootHash };
  }
}

/**
 * Утилита для работы с Merkle Tree
 */
export class MerkleTreeUtils {
  /**
   * Вычисляет корневой хеш из набора файлов
   * 
   * @param files - Файлы с хешами
   * @param algorithm - Алгоритм хеширования
   * @returns Корневой хеш
   */
  static computeRootHash(files: FileHash[], algorithm: HashAlgorithm = 'SHA-256'): string {
    const tree = new MerkleTree(algorithm);
    return tree.build(files);
  }

  /**
   * Верифицирует набор файлов против корневого хеша
   * 
   * @param files - Файлы для верификации
   * @param expectedRoot - Ожидаемый корневой хеш
   * @param algorithm - Алгоритм хеширования
   * @returns Результат верификации
   */
  static verifyFiles(
    files: FileHash[],
    expectedRoot: string,
    algorithm: HashAlgorithm = 'SHA-256'
  ): MerkleVerificationResult {
    const tree = new MerkleTree(algorithm);
    const computedRoot = tree.build(files);

    return {
      verified: computedRoot === expectedRoot,
      computedRoot,
      expectedRoot,
      errors: computedRoot === expectedRoot ? [] : ['Корневой хеш не совпадает']
    };
  }

  /**
   * Создает компактный proof для набора файлов
   * 
   * @param tree - Дерево Меркла
   * @param filePaths - Пути файлов для proof
   * @returns Массив proof объектов
   */
  static createBatchProof(tree: MerkleTree, filePaths: string[]): MerkleProof[] {
    return filePaths
      .map(path => tree.generateProof(path))
      .filter((proof): proof is MerkleProof => proof !== null);
  }
}

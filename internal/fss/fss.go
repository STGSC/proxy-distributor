package fss

import (
	"crypto/sha256"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/klauspost/compress/zstd"
)

// FSS 文件型存储系统
type FSS struct {
	dataDir string
	mutex   sync.RWMutex
}

// New 创建新的FSS实例
func New(dataDir string) *FSS {
	return &FSS{
		dataDir: dataDir,
	}
}

// AtomicWrite 原子写入文件
func (f *FSS) AtomicWrite(filename string, data []byte) error {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	// 确保目录存在
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("创建目录失败: %w", err)
	}

	// 创建临时文件
	tmpFile := filename + ".tmp"
	file, err := os.Create(tmpFile)
	if err != nil {
		return fmt.Errorf("创建临时文件失败: %w", err)
	}
	defer file.Close()

	// 写入数据
	if _, err := file.Write(data); err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("写入数据失败: %w", err)
	}

	// 同步到磁盘
	if err := file.Sync(); err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("同步文件失败: %w", err)
	}

	// 关闭文件
	if err := file.Close(); err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("关闭文件失败: %w", err)
	}

	// 原子重命名
	if err := os.Rename(tmpFile, filename); err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("重命名文件失败: %w", err)
	}

	// 同步目录（在Windows上可能会失败，忽略错误）
	dirFile, err := os.Open(dir)
	if err == nil {
		dirFile.Sync() // 忽略同步错误
		dirFile.Close()
	}

	return nil
}

// Read 读取文件
func (f *FSS) Read(filename string) ([]byte, error) {
	f.mutex.RLock()
	defer f.mutex.RUnlock()

	return os.ReadFile(filename)
}

// ReadJSON 读取JSON文件
func (f *FSS) ReadJSON(filename string, v interface{}) error {
	data, err := f.Read(filename)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, v)
}

// WriteJSON 写入JSON文件
func (f *FSS) WriteJSON(filename string, v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化JSON失败: %w", err)
	}

	return f.AtomicWrite(filename, data)
}

// ReadGob 读取Gob文件
func (f *FSS) ReadGob(filename string, v interface{}) error {
	f.mutex.RLock()
	defer f.mutex.RUnlock()

	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	decoder := gob.NewDecoder(file)
	return decoder.Decode(v)
}

// WriteGob 写入Gob文件
func (f *FSS) WriteGob(filename string, v interface{}) error {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	// 确保目录存在
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("创建目录失败: %w", err)
	}

	// 创建临时文件
	tmpFile := filename + ".tmp"
	file, err := os.Create(tmpFile)
	if err != nil {
		return fmt.Errorf("创建临时文件失败: %w", err)
	}
	defer file.Close()

	encoder := gob.NewEncoder(file)
	if err := encoder.Encode(v); err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("编码Gob失败: %w", err)
	}

	// 同步到磁盘
	if err := file.Sync(); err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("同步文件失败: %w", err)
	}

	// 关闭文件
	if err := file.Close(); err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("关闭文件失败: %w", err)
	}

	// 原子重命名
	if err := os.Rename(tmpFile, filename); err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("重命名文件失败: %w", err)
	}

	return nil
}

// ReadCompressed 读取压缩文件
func (f *FSS) ReadCompressed(filename string) ([]byte, error) {
	f.mutex.RLock()
	defer f.mutex.RUnlock()

	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	decoder, err := zstd.NewReader(file)
	if err != nil {
		return nil, fmt.Errorf("创建解压器失败: %w", err)
	}
	defer decoder.Close()

	return io.ReadAll(decoder)
}

// WriteCompressed 写入压缩文件
func (f *FSS) WriteCompressed(filename string, data []byte) error {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	// 确保目录存在
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("创建目录失败: %w", err)
	}

	// 创建临时文件
	tmpFile := filename + ".tmp"
	file, err := os.Create(tmpFile)
	if err != nil {
		return fmt.Errorf("创建临时文件失败: %w", err)
	}
	defer file.Close()

	encoder, err := zstd.NewWriter(file)
	if err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("创建压缩器失败: %w", err)
	}

	if _, err := encoder.Write(data); err != nil {
		encoder.Close()
		os.Remove(tmpFile)
		return fmt.Errorf("写入压缩数据失败: %w", err)
	}

	if err := encoder.Close(); err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("关闭压缩器失败: %w", err)
	}

	// 同步到磁盘
	if err := file.Sync(); err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("同步文件失败: %w", err)
	}

	// 关闭文件
	if err := file.Close(); err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("关闭文件失败: %w", err)
	}

	// 原子重命名
	if err := os.Rename(tmpFile, filename); err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("重命名文件失败: %w", err)
	}

	return nil
}

// WAL WAL日志结构
type WAL struct {
	fss      *FSS
	filename string
	mutex    sync.RWMutex
}

// NewWAL 创建新的WAL实例
func (f *FSS) NewWAL(filename string) *WAL {
	return &WAL{
		fss:      f,
		filename: filename,
	}
}

// Append 追加WAL记录
func (w *WAL) Append(record interface{}) error {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	// 序列化记录
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("序列化WAL记录失败: %w", err)
	}

	// 确保目录存在
	dir := filepath.Dir(w.filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("创建WAL目录失败: %w", err)
	}

	// 追加到文件
	file, err := os.OpenFile(w.filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("打开WAL文件失败: %w", err)
	}
	defer file.Close()

	// 写入记录（每行一个JSON）
	if _, err := file.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("写入WAL记录失败: %w", err)
	}

	// 同步到磁盘
	if err := file.Sync(); err != nil {
		return fmt.Errorf("同步WAL文件失败: %w", err)
	}

	return nil
}

// Replay 重放WAL记录
func (w *WAL) Replay(handler func(record json.RawMessage) error) error {
	w.mutex.RLock()
	defer w.mutex.RUnlock()

	file, err := os.Open(w.filename)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // WAL文件不存在，无需重放
		}
		return fmt.Errorf("打开WAL文件失败: %w", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	for {
		var record json.RawMessage
		if err := decoder.Decode(&record); err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("解码WAL记录失败: %w", err)
		}

		if err := handler(record); err != nil {
			return fmt.Errorf("处理WAL记录失败: %w", err)
		}
	}

	return nil
}

// Truncate 截断WAL文件
func (w *WAL) Truncate() error {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	return os.Truncate(w.filename, 0)
}

// GetDataDir 获取数据目录
func (f *FSS) GetDataDir() string {
	return f.dataDir
}

// GetPath 获取文件完整路径
func (f *FSS) GetPath(relPath string) string {
	return filepath.Join(f.dataDir, relPath)
}

// EnsureDir 确保目录存在
func (f *FSS) EnsureDir(relPath string) error {
	dir := f.GetPath(relPath)
	return os.MkdirAll(dir, 0755)
}

// FileExists 检查文件是否存在
func (f *FSS) FileExists(relPath string) bool {
	_, err := os.Stat(f.GetPath(relPath))
	return !os.IsNotExist(err)
}

// GetFileHash 获取文件SHA256哈希
func (f *FSS) GetFileHash(relPath string) (string, error) {
	data, err := f.Read(f.GetPath(relPath))
	if err != nil {
		return "", err
	}

	hash := sha256.Sum256(data)
	return fmt.Sprintf("%x", hash), nil
}

// ListFiles 列出目录中的文件
func (f *FSS) ListFiles(relPath string) ([]string, error) {
	dir := f.GetPath(relPath)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}

	var files []string
	for _, entry := range entries {
		if !entry.IsDir() {
			files = append(files, entry.Name())
		}
	}

	return files, nil
}

// RemoveFile 删除文件
func (f *FSS) RemoveFile(relPath string) error {
	return os.Remove(f.GetPath(relPath))
}

// GetFileInfo 获取文件信息
func (f *FSS) GetFileInfo(relPath string) (os.FileInfo, error) {
	return os.Stat(f.GetPath(relPath))
}

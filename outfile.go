package dnp3

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"strings"
	"sync"
	"time"
)

// The outstation's side of sequential file transfer (IEEE 1815-2012
// 4.4.17 to 4.4.19 and 5.3): authentication keys, open, read, write,
// close, abort, delete, file information and directory files, over a
// FileStore (object storage in the dnp3-server kind; never the local
// disk). Answers are always immediate: the g70v4, v5, v6 and v7 objects of
// a response are event objects and ask for confirmation (5.3.8 rule 1);
// an idle handle is closed and reported by a g70v6 event (status 17) in
// the configured class (4.4.17.1.1).

// ErrFileNotFound is returned by a FileStore for a name it does not hold,
// ErrFileDenied for one the requestor may not use.
var (
	ErrFileNotFound = errors.New("file not found")
	ErrFileDenied   = errors.New("file access denied")
)

// FileInfo describes a file or directory. Size is the length of a file,
// or the number of entries of a directory (5.3.5).
type FileInfo struct {
	Name        string // base name
	Dir         bool
	Size        uint32
	Created     time.Time
	Permissions uint16
}

// FileStore holds an outstation's files. Paths are the file name of the
// request without separators at either end, segments joined by "/"
// ("" is the root directory).
type FileStore interface {
	Stat(ctx context.Context, path string) (FileInfo, error)
	List(ctx context.Context, dir string) ([]FileInfo, error)
	Read(ctx context.Context, path string) ([]byte, error)
	Write(ctx context.Context, path string, data []byte, created time.Time, perms uint16) error
	Delete(ctx context.Context, path string) error
}

// FileUser is a user of AUTHENTICATE_FILE: files are readable, and
// writable and deletable with Write.
type FileUser struct {
	Password Secret
	Write    bool
}

// FileRights are the rights of a request without a valid key.
type FileRights struct{ Read, Write bool }

// Permission bits of every class (owner, group, world: 5.3.2 keeps them
// equal).
const (
	PermRead  = 0x124
	PermWrite = 0x092
	PermExec  = 0x049
)

// OutstationFiles configures file transfer; one value may serve several
// associations (handles and locks are then shared: 5.3.8 rule 9).
type OutstationFiles struct {
	Store    FileStore
	MaxBlock int           // largest block (default 1024)
	MaxOpen  int           // files open at once (default 4; rule 10)
	MaxSize  int           // largest file written (default 16 MiB)
	Idle     time.Duration // inactivity before a handle closes (default 5 min, at most 1 h; rule 12)
	Class    int           // class of spontaneous file events (default 3)
	KeyLife  time.Duration // an authentication key's life (default 1 min)
	ReadOnly bool          // refuse every write and delete
	Users    map[string]FileUser
	// Guest are the rights with key 0 (5.3.1); nil: read and write when no
	// users are configured, nothing otherwise.
	Guest *FileRights
	// Changed reports a file written ("written") or deleted ("deleted").
	Changed func(ctx context.Context, path, op string, size int)

	mu     sync.Mutex
	next   uint32
	open   map[uint32]*openFile
	locked map[string]uint32
	keys   map[uint32]fileKey
}

type fileKey struct {
	rights  FileRights
	expires time.Time
}

type openFile struct {
	path     string
	assoc    *Association
	write    bool
	data     []byte // read: the content; write: what was received
	size     uint32 // announced size (write), 0xFFFFFFFF unknown
	maxBlock int
	block    uint32 // next block expected
	used     time.Time
	created  time.Time
	perms    uint16
}

func (fs *OutstationFiles) init() {
	if fs.open != nil {
		return
	}
	if fs.MaxBlock <= 0 {
		fs.MaxBlock = 1024
	}
	if fs.MaxOpen <= 0 {
		fs.MaxOpen = 4
	}
	if fs.MaxSize <= 0 {
		fs.MaxSize = 16 << 20
	}
	if fs.Idle <= 0 {
		fs.Idle = 5 * time.Minute
	}
	fs.Idle = min(fs.Idle, time.Hour)
	if fs.Class < 1 || fs.Class > 3 {
		fs.Class = 3
	}
	if fs.KeyLife <= 0 {
		fs.KeyLife = time.Minute
	}
	var b [4]byte
	_, _ = rand.Read(b[:])
	fs.next = binary.LittleEndian.Uint32(b[:]) & 0x7FFFFFFF
	fs.open, fs.locked, fs.keys = map[uint32]*openFile{}, map[string]uint32{}, map[uint32]fileKey{}
}

// rights resolves an authentication key (used once: 5.3.1).
func (fs *OutstationFiles) rights(key uint32) FileRights {
	if key != 0 {
		k, ok := fs.keys[key]
		delete(fs.keys, key)
		if ok && time.Now().Before(k.expires) {
			return k.rights
		}
	}
	if fs.Guest != nil {
		return *fs.Guest
	}
	if len(fs.Users) == 0 {
		return FileRights{Read: true, Write: true}
	}
	return FileRights{}
}

// guestPerms are the permission bits reported to an unidentified
// requestor (5.3.2: the requestor's privileges).
func (fs *OutstationFiles) guestPerms(file uint16) uint16 {
	r := fs.rightsNoKey()
	var p uint16 = PermExec
	if r.Read {
		p |= PermRead
	}
	if r.Write && !fs.ReadOnly {
		p |= PermWrite
	}
	if file != 0 {
		p &= file
	}
	return p
}

func (fs *OutstationFiles) rightsNoKey() FileRights {
	if fs.Guest != nil {
		return *fs.Guest
	}
	return FileRights{Read: len(fs.Users) == 0, Write: len(fs.Users) == 0}
}

// FilePath turns a request's file name into a store path: "\" and "/"
// both separate segments; "." and ".." are refused.
func FilePath(name string) (string, bool) {
	parts := strings.FieldsFunc(name, func(r rune) bool { return r == '\\' || r == '/' })
	for _, p := range parts {
		if p == "." || p == ".." || strings.ContainsRune(p, 0) {
			return "", false
		}
	}
	return strings.Join(parts, "/"), true
}

// File status codes (Table 11-8).
const (
	fsSuccess       = 0
	fsDenied        = 1
	fsInvalidMode   = 2
	fsNotFound      = 3
	fsLocked        = 4
	fsTooManyOpen   = 5
	fsInvalidHandle = 6
	fsBlockSize     = 7
	fsExpired       = 17
	fsOverrun       = 18
	fsFatal         = 19
	fsBlockSequence = 20
)

// fileChunk is one response object of g70 variation v (an event object
// asking for confirmation, except the g70v2 authentication answer).
func fileChunk(v uint8, obj []byte) chunk {
	b, _ := EncodeBlock(70, v, QFreeFormat, []Point{{Raw: obj}})
	return chunk{data: b, confirm: v != 2}
}

// fileRequest answers the file function codes (and READ or WRITE of
// g70v5).
func (a *Association) fileRequest(ctx context.Context, fc byte, objs []byte) ([]chunk, IIN) {
	fs := a.cfg.Files
	if fs == nil || a.fileStore() == nil {
		return nil, IINNoFuncCodeSupport
	}
	blocks, err := ParseObjects(objs, true)
	if err != nil || len(blocks) != 1 || len(blocks[0].Points) != 1 || blocks[0].Header.Group != 70 {
		return nil, IINParameterError
	}
	h, raw := blocks[0].Header, blocks[0].Points[0].Raw
	fs.mu.Lock()
	fs.init()
	fs.mu.Unlock()
	switch {
	case fc == FCAuthenticateFile && h.Var == 2:
		req, err := ParseFileAuth(raw)
		if err != nil {
			return nil, IINParameterError
		}
		return []chunk{fileChunk(2, FileAuth{Key: fs.authenticate(req)}.Encode())}, 0
	case (fc == FCOpenFile || fc == FCDeleteFile) && h.Var == 3:
		cmd, err := ParseFileCommand(raw)
		if err != nil {
			return nil, IINParameterError
		}
		if fc == FCDeleteFile {
			return []chunk{fileChunk(4, FileStatus{RequestID: cmd.RequestID, Status: a.deleteFile(ctx, cmd)}.Encode())}, 0
		}
		return []chunk{fileChunk(4, a.openFile(ctx, cmd).Encode())}, 0
	case (fc == FCCloseFile || fc == FCAbortFile) && h.Var == 4:
		st, err := ParseFileStatus(raw)
		if err != nil {
			return nil, IINParameterError
		}
		st.Status = a.closeFile(ctx, st.Handle, fc == FCAbortFile)
		return []chunk{fileChunk(4, st.Encode())}, 0
	case fc == FCGetFileInfo && h.Var == 7:
		d, err := ParseFileDescriptor(raw)
		if err != nil {
			return nil, IINParameterError
		}
		return []chunk{a.fileInfo(ctx, d)}, 0
	case fc == FCRead && h.Var == 5:
		t, err := ParseFileTransport(raw)
		if err != nil {
			return nil, IINParameterError
		}
		return []chunk{a.readBlock(t)}, 0
	case fc == FCWrite && h.Var == 5:
		t, err := ParseFileTransport(raw)
		if err != nil {
			return nil, IINParameterError
		}
		return []chunk{a.writeBlock(ctx, t)}, 0
	}
	return nil, IINObjectUnknown
}

func (fs *OutstationFiles) authenticate(req FileAuth) uint32 {
	u, ok := fs.Users[req.User]
	if !ok || subtle.ConstantTimeCompare([]byte(u.Password), []byte(req.Password)) != 1 {
		return 0
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	now := time.Now()
	for k, v := range fs.keys {
		if now.After(v.expires) {
			delete(fs.keys, k)
		}
	}
	for {
		var b [4]byte
		_, _ = rand.Read(b[:])
		k := binary.LittleEndian.Uint32(b[:])
		if _, used := fs.keys[k]; k != 0 && !used {
			fs.keys[k] = fileKey{rights: FileRights{Read: true, Write: u.Write}, expires: now.Add(fs.KeyLife)}
			return k
		}
	}
}

func (a *Association) openFile(ctx context.Context, cmd FileCommand) FileStatus {
	fs := a.cfg.Files
	out := FileStatus{RequestID: cmd.RequestID}
	fail := func(s uint8) FileStatus { out.Status = s; return out }
	path, ok := FilePath(cmd.Name)
	if !ok {
		return fail(fsNotFound)
	}
	fs.mu.Lock()
	rights := fs.rights(cmd.AuthKey)
	_, locked := fs.locked[path]
	nOpen := len(fs.open)
	fs.mu.Unlock()
	write := cmd.Mode == FileModeWrite || cmd.Mode == FileModeAppend
	switch {
	case cmd.Mode != FileModeRead && !write:
		return fail(fsInvalidMode)
	case write && (!rights.Write || fs.ReadOnly), !write && !rights.Read:
		return fail(fsDenied)
	case locked:
		return fail(fsLocked)
	case nOpen >= fs.MaxOpen:
		return fail(fsTooManyOpen)
	}
	info, err := a.fileStore().Stat(ctx, path)
	exists := err == nil
	switch {
	case errors.Is(err, ErrFileDenied):
		return fail(fsDenied)
	case err != nil && !errors.Is(err, ErrFileNotFound):
		a.cfg.Log.Warn("DNP3 file not opened", "file", path, "error", err)
		return fail(fsFatal)
	case !exists && !write:
		return fail(fsNotFound)
	case exists && info.Dir && write, write && path == "":
		return fail(fsDenied) // rule 15
	case exists && info.Permissions != 0 && ((write && info.Permissions&PermWrite == 0) || (!write && info.Permissions&PermRead == 0)):
		return fail(fsDenied)
	}
	of := &openFile{path: path, assoc: a, write: write, size: cmd.Size, used: time.Now(), created: cmd.Created, perms: cmd.Permissions}
	of.maxBlock = fs.MaxBlock
	if cmd.MaxBlock > 0 {
		of.maxBlock = min(of.maxBlock, int(cmd.MaxBlock))
	}
	if !write && of.maxBlock > a.cfg.MaxFragment-24 {
		of.maxBlock = a.cfg.MaxFragment - 24
	}
	switch {
	case !write && info.Dir:
		ents, err := a.fileStore().List(ctx, path)
		if err != nil {
			return fail(fsFatal)
		}
		for _, e := range ents {
			typ := uint16(1)
			if e.Dir {
				typ = 0
			}
			of.data = append(of.data, FileDescriptor{Type: typ, Size: e.Size, Created: e.Created, Permissions: fs.guestPerms(e.Permissions), Name: e.Name}.Encode()...)
		}
	case !write:
		if of.data, err = a.fileStore().Read(ctx, path); err != nil {
			return fail(fsFatal)
		}
	case cmd.Mode == FileModeAppend && exists:
		if of.data, err = a.fileStore().Read(ctx, path); err != nil {
			return fail(fsFatal)
		}
		of.size = addSize(cmd.Size, len(of.data))
	}
	fs.mu.Lock()
	if _, taken := fs.locked[path]; taken {
		fs.mu.Unlock()
		return fail(fsLocked)
	}
	for {
		fs.next++
		if _, used := fs.open[fs.next]; fs.next != 0 && !used {
			break
		}
	}
	h := fs.next
	fs.open[h], fs.locked[path] = of, h
	fs.mu.Unlock()
	out.Handle, out.MaxBlock = h, uint16(of.maxBlock)
	if write {
		// The size requested is repeated (as EX 4-29 shows; F-601).
		out.Size = cmd.Size
	} else {
		out.Size = uint32(len(of.data))
	}
	return out
}

func addSize(announced uint32, have int) uint32 {
	if announced == 0xFFFFFFFF {
		return announced
	}
	return announced + uint32(have)
}

// take returns an open file of this association, touching it.
func (a *Association) take(h uint32) *openFile {
	fs := a.cfg.Files
	fs.mu.Lock()
	defer fs.mu.Unlock()
	of := fs.open[h]
	if of == nil || of.assoc != a {
		return nil
	}
	of.used = time.Now()
	return of
}

func (fs *OutstationFiles) release(h uint32) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if of := fs.open[h]; of != nil {
		delete(fs.locked, of.path)
		delete(fs.open, h)
	}
}

func (a *Association) closeFile(ctx context.Context, h uint32, abort bool) uint8 {
	fs := a.cfg.Files
	of := a.take(h)
	if of == nil {
		return fsInvalidHandle
	}
	fs.release(h)
	if !of.write || abort {
		return fsSuccess
	}
	return a.commit(ctx, of)
}

func (a *Association) commit(ctx context.Context, of *openFile) uint8 {
	fs := a.cfg.Files
	if err := a.fileStore().Write(ctx, of.path, of.data, of.created, of.perms); errors.Is(err, ErrFileDenied) {
		return fsDenied
	} else if err != nil {
		a.cfg.Log.Warn("DNP3 file not stored", "file", of.path, "error", err)
		return fsFatal
	}
	if fs.Changed != nil {
		fs.Changed(ctx, of.path, "written", len(of.data))
	}
	return fsSuccess
}

func (a *Association) deleteFile(ctx context.Context, cmd FileCommand) uint8 {
	fs := a.cfg.Files
	path, ok := FilePath(cmd.Name)
	if !ok {
		return fsNotFound
	}
	fs.mu.Lock()
	rights := fs.rights(cmd.AuthKey)
	_, locked := fs.locked[path]
	fs.mu.Unlock()
	switch {
	case !rights.Write || fs.ReadOnly || path == "":
		return fsDenied // rule 16 for the root
	case locked:
		return fsLocked // rule 11
	}
	info, err := a.fileStore().Stat(ctx, path)
	switch {
	case errors.Is(err, ErrFileNotFound):
		return fsNotFound
	case err != nil:
		return fsFatal
	case info.Dir || (info.Permissions != 0 && info.Permissions&PermWrite == 0):
		return fsDenied
	}
	if err := a.fileStore().Delete(ctx, path); err != nil {
		if errors.Is(err, ErrFileNotFound) {
			return fsNotFound
		}
		if errors.Is(err, ErrFileDenied) {
			return fsDenied
		}
		return fsFatal
	}
	if fs.Changed != nil {
		fs.Changed(ctx, path, "deleted", 0)
	}
	return fsSuccess
}

func (a *Association) fileInfo(ctx context.Context, d FileDescriptor) chunk {
	fs := a.cfg.Files
	missing := fileChunk(4, FileStatus{RequestID: d.RequestID, Status: fsNotFound}.Encode())
	path, ok := FilePath(d.Name)
	if !ok {
		return missing
	}
	if !fs.rightsNoKey().Read {
		return fileChunk(4, FileStatus{RequestID: d.RequestID, Status: fsDenied}.Encode())
	}
	info, err := a.fileStore().Stat(ctx, path)
	if errors.Is(err, ErrFileDenied) {
		return fileChunk(4, FileStatus{RequestID: d.RequestID, Status: fsDenied}.Encode())
	}
	if err != nil {
		return missing
	}
	d.Type, d.Size, d.Created, d.Permissions = 1, info.Size, info.Created, fs.guestPerms(info.Permissions)
	if info.Dir {
		d.Type = 0
	}
	return fileChunk(7, d.Encode())
}

func (a *Association) readBlock(t FileTransport) chunk {
	fs := a.cfg.Files
	bad := func(s uint8) chunk {
		return fileChunk(6, FileTransportStatus{Handle: t.Handle, Block: t.Block, Status: s}.Encode())
	}
	of := a.take(t.Handle)
	switch {
	case of == nil:
		return bad(fsInvalidHandle)
	case of.write:
		fs.release(t.Handle) // rule 13
		return bad(fsInvalidMode)
	case t.Block != of.block:
		fs.release(t.Handle)
		return bad(fsBlockSequence)
	}
	off := int(t.Block) * of.maxBlock
	end := min(off+of.maxBlock, len(of.data))
	last := end == len(of.data)
	of.block++
	return fileChunk(5, FileTransport{Handle: t.Handle, Block: t.Block, Last: last, Data: of.data[off:end]}.Encode())
}

func (a *Association) writeBlock(ctx context.Context, t FileTransport) chunk {
	fs := a.cfg.Files
	answer := func(s uint8) chunk {
		return fileChunk(6, FileTransportStatus{Handle: t.Handle, Block: t.Block, Last: t.Last, Status: s}.Encode())
	}
	of := a.take(t.Handle)
	fail := func(s uint8) chunk { fs.release(t.Handle); return answer(s) } // rule 14
	switch {
	case of == nil:
		return answer(fsInvalidHandle)
	case !of.write:
		return fail(fsInvalidMode)
	case t.Block != of.block:
		return fail(fsBlockSequence)
	case len(t.Data) > of.maxBlock:
		return fail(fsBlockSize)
	case len(of.data)+len(t.Data) > fs.MaxSize, of.size != 0xFFFFFFFF && uint64(len(of.data)+len(t.Data)) > uint64(of.size):
		return fail(fsOverrun) // rule 7
	}
	of.data = append(of.data, t.Data...)
	of.block++
	return answer(fsSuccess)
}

// expireFiles closes this association's idle handles and reports each
// with a g70v6 event (4.4.17.1.1).
func (a *Association) expireFiles(ctx context.Context) {
	fs := a.cfg.Files
	if fs == nil {
		return
	}
	fs.mu.Lock()
	if fs.open == nil {
		fs.mu.Unlock()
		return
	}
	var gone []uint32
	for h, of := range fs.open {
		if of.assoc == a && time.Since(of.used) > fs.Idle {
			gone = append(gone, h)
			delete(fs.locked, of.path)
			delete(fs.open, h)
		}
	}
	class := fs.Class
	fs.mu.Unlock()
	for _, h := range gone {
		a.cfg.Events.Add(ctx, Event{Class: class, Group: 70, Var: 6, Raw: FileTransportStatus{Handle: h, Status: fsExpired}.Encode(), Time: time.Now()})
	}
}

// fileStore is the association's file store.
func (a *Association) fileStore() FileStore {
	if a.cfg.FileStore != nil {
		return a.cfg.FileStore
	}
	if a.cfg.Files != nil {
		return a.cfg.Files.Store
	}
	return nil
}

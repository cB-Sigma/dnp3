package dnp3_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cB-Sigma/dnp3"
)

// memFiles is an in-memory dnp3.FileStore for the outstation tests.
type memFiles struct {
	mu    sync.Mutex
	files map[string][]byte
	meta  map[string]dnp3.FileInfo
	dirs  map[string]bool // empty directories
}

func newMemFiles() *memFiles {
	return &memFiles{files: map[string][]byte{}, meta: map[string]dnp3.FileInfo{}, dirs: map[string]bool{}}
}

func (m *memFiles) put(path string, data []byte, created time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.files[path] = data
	m.meta[path] = dnp3.FileInfo{Created: created, Permissions: 0x1FF}
}

func (m *memFiles) children(dir string) []dnp3.FileInfo {
	pre := ""
	if dir != "" {
		pre = dir + "/"
	}
	seen := map[string]bool{}
	var out []dnp3.FileInfo
	names := append([]string{}, keys(m.files)...)
	for d := range m.dirs {
		names = append(names, d+"/")
	}
	sort.Strings(names)
	for _, k := range names {
		if !strings.HasPrefix(k, pre) || k == pre {
			continue
		}
		rest := strings.TrimPrefix(k, pre)
		if i := strings.IndexByte(rest, '/'); i >= 0 {
			n := rest[:i]
			if !seen[n] {
				seen[n] = true
				out = append(out, dnp3.FileInfo{Name: n, Dir: true, Size: uint32(len(m.children(pre + n)))})
			}
			continue
		}
		fi := m.meta[k]
		fi.Name, fi.Size = rest, uint32(len(m.files[k]))
		out = append(out, fi)
	}
	return out
}

func keys(m map[string][]byte) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func (m *memFiles) Stat(_ context.Context, path string) (dnp3.FileInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if b, ok := m.files[path]; ok {
		fi := m.meta[path]
		fi.Name, fi.Size = path[strings.LastIndexByte(path, '/')+1:], uint32(len(b))
		return fi, nil
	}
	if path == "" || m.dirs[path] || len(m.children(path)) > 0 {
		return dnp3.FileInfo{Name: path[strings.LastIndexByte(path, '/')+1:], Dir: true, Size: uint32(len(m.children(path)))}, nil
	}
	return dnp3.FileInfo{}, dnp3.ErrFileNotFound
}

func (m *memFiles) List(_ context.Context, dir string) ([]dnp3.FileInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.children(dir), nil
}

func (m *memFiles) Read(_ context.Context, path string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.files[path]
	if !ok {
		return nil, dnp3.ErrFileNotFound
	}
	return append([]byte(nil), b...), nil
}

func (m *memFiles) Write(_ context.Context, path string, data []byte, created time.Time, perms uint16) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.files[path] = append([]byte(nil), data...)
	m.meta[path] = dnp3.FileInfo{Created: created, Permissions: perms}
	return nil
}

func (m *memFiles) Delete(_ context.Context, path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.files[path]; !ok {
		return dnp3.ErrFileNotFound
	}
	delete(m.files, path)
	return nil
}

func (m *memFiles) get(path string) ([]byte, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.files[path]
	return b, ok
}

// fileRequest sends fc with objects and returns the single response
// fragment.
func fileRequest(t *testing.T, m *dnp3.Master, fc byte, objs []byte) dnp3.Fragment {
	t.Helper()
	frags, err := m.Request(context.Background(), fc, objs)
	var rej *dnp3.RejectedError
	if err != nil && !errors.As(err, &rej) {
		t.Fatalf("%s: %v", dnp3.FuncName(fc), err)
	}
	if len(frags) != 1 {
		t.Fatalf("%s: %d fragments", dnp3.FuncName(fc), len(frags))
	}
	return frags[0]
}

// fileObject is the object data of the single g70 object of a response.
func fileObject(t *testing.T, f dnp3.Fragment, v uint8) []byte {
	t.Helper()
	bl := blocks(t, f, true)
	if len(bl) != 1 || bl[0].Header.Group != 70 || bl[0].Header.Var != v || len(bl[0].Points) != 1 {
		t.Fatalf("want one g70v%d, got % X", v, f.Objects)
	}
	return bl[0].Points[0].Raw
}

// Covers: SIG-IPE-1621
func TestOutstationFileTransferExamples(t *testing.T) {
	mem := newMemFiles()
	a5 := bytes.Repeat([]byte{0xA5}, 42)
	mem.put("XYZ", a5, time.Time{})
	o := startOutstation(t, func(c *dnp3.OutstationConfig) {
		c.Files = &dnp3.OutstationFiles{Store: mem, MaxBlock: 192,
			Users: map[string]dnp3.FileUser{"SCADA": {Password: "ZEBRA", Write: true}},
			Guest: &dnp3.FileRights{Read: true, Write: true}}
	})
	m := o.master(t, nil, nil)
	evCon := func(f dnp3.Fragment) {
		t.Helper()
		if f.Control&0xE0 != 0xE0 {
			t.Errorf("file event objects are sent with FIR, FIN and CON (5.3.8 rule 1): control %02X", f.Control)
		}
	}

	// EX 4-29: open "ABC" for writing, 2048 octets, blocks of 2048 asked;
	// the outstation answers at once with a block size of 192.
	f := fileRequest(t, m, dnp3.FCOpenFile, hx(t, "46 03 5B 01 1D 00 1A 00 03 00 80 4E 8F 1F EB 00 FF 01 00 00 00 00 00 08 00 00 02 00 00 08 37 01 41 42 43"))
	evCon(f)
	st := fileObject(t, f, 4)
	h := binary.LittleEndian.Uint32(st)
	if h == 0 {
		t.Fatal("handle 0")
	}
	if want := append(le32(h), hx(t, "00 08 00 00 C0 00 37 01 00")...); !bytes.Equal(f.Objects, append(hx(t, "46 04 5B 01 0D 00"), want...)) {
		t.Fatalf("open response % X", f.Objects)
	}
	// EX 5-3: blocks of 192 octets; the last (block 10, 128 octets) is
	// marked and acknowledged with a g70v6 status 0.
	data := bytes.Repeat([]byte{0xA5}, 2048)
	for blk := uint32(0); blk <= 10; blk++ {
		last := blk == 10
		chunk := data[blk*192 : min(int(blk+1)*192, 2048)]
		field := blk
		if last {
			field |= 1 << 31
		}
		obj := append(append(le32(h), le32(field)...), chunk...)
		req := binary.LittleEndian.AppendUint16(hx(t, "46 05 5B 01"), uint16(len(obj)))
		f = fileRequest(t, m, dnp3.FCWrite, append(req, obj...))
		evCon(f)
		want := append(append(hx(t, "46 06 5B 01 09 00"), le32(h)...), le32(field)...)
		if !bytes.Equal(f.Objects, append(want, 0)) {
			t.Fatalf("write block %d: % X", blk, f.Objects)
		}
	}
	// EX 4-30: close; the response repeats the request's object.
	closeObj := append(append(hx(t, "46 04 5B 01 0D 00"), le32(h)...), hx(t, "00 00 00 00 00 00 37 01 00")...)
	f = fileRequest(t, m, dnp3.FCCloseFile, closeObj)
	evCon(f)
	if !bytes.Equal(f.Objects, closeObj) {
		t.Fatalf("close response % X", f.Objects)
	}
	if b, ok := mem.get("ABC"); !ok || !bytes.Equal(b, data) {
		t.Fatalf("stored %d octets", len(b))
	}
	// EX 4-33: file information: type 1, 2048 octets, the time and
	// permissions given at open (5.3.8 rule 3), request ID 0x0137.
	f = fileRequest(t, m, dnp3.FCGetFileInfo, hx(t, "46 07 5B 01 17 00 14 00 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 37 01 41 42 43"))
	evCon(f)
	if !bytes.Equal(f.Objects, hx(t, "46 07 5B 01 17 00 14 00 03 00 01 00 00 08 00 00 80 4E 8F 1F EB 00 FF 01 37 01 41 42 43")) {
		t.Fatalf("file info % X", f.Objects)
	}
	// EX 5-2: read block 2 of a 42-octet file opened with blocks of 14: the
	// last block, 14 octets.
	cmd := dnp3.FileCommand{Mode: dnp3.FileModeRead, MaxBlock: 14, RequestID: 9, Name: "XYZ"}.Encode()
	f = fileRequest(t, m, dnp3.FCOpenFile, append(binary.LittleEndian.AppendUint16(hx(t, "46 03 5B 01"), uint16(len(cmd))), cmd...))
	rs, _ := dnp3.ParseFileStatus(fileObject(t, f, 4))
	if rs.Status != 0 || rs.Size != 42 || rs.MaxBlock != 14 {
		t.Fatalf("open for reading: %+v", rs)
	}
	for blk := uint32(0); blk <= 2; blk++ {
		f = fileRequest(t, m, dnp3.FCRead, append(append(hx(t, "46 05 5B 01 08 00"), le32(rs.Handle)...), le32(blk)...))
		evCon(f)
		if blk < 2 {
			continue
		}
		want := append(append(hx(t, "46 05 5B 01 16 00"), le32(rs.Handle)...), hx(t, "02 00 00 80")...)
		if !bytes.Equal(f.Objects, append(want, a5[:14]...)) {
			t.Fatalf("read block 2: % X", f.Objects)
		}
	}
	fileRequest(t, m, dnp3.FCCloseFile, append(hx(t, "46 04 5B 01 0C 00"), dnp3.FileStatus{Handle: rs.Handle, RequestID: 9}.Encode()...))
	// EX 4-31: delete "ABC": handle, size and block size zero.
	f = fileRequest(t, m, dnp3.FCDeleteFile, hx(t, "46 03 5B 01 1D 00 1A 00 03 00 00 00 00 00 00 00 FF 01 00 00 00 00 00 00 00 00 00 00 00 00 37 01 41 42 43"))
	evCon(f)
	if !bytes.Equal(f.Objects, hx(t, "46 04 5B 01 0D 00 00 00 00 00 00 00 00 00 00 00 37 01 00")) {
		t.Fatalf("delete response % X", f.Objects)
	}
	if _, ok := mem.get("ABC"); ok {
		t.Fatal("not deleted")
	}
	// EX 4-34: authenticate user SCADA, password ZEBRA; the answer carries
	// only a key (no names), and is not an event (no CON). The size prefix
	// is the object's 22 octets, not the example's 0x15 (F-582).
	f = fileRequest(t, m, dnp3.FCAuthenticateFile, hx(t, "46 02 5B 01 16 00 0C 00 05 00 11 00 05 00 00 00 00 00 53 43 41 44 41 5A 45 42 52 41"))
	if f.Control&dnp3.AppCON != 0 {
		t.Errorf("authentication answer asks for confirmation: %02X", f.Control)
	}
	key := binary.LittleEndian.Uint32(fileObject(t, f, 2)[8:])
	if key == 0 || !bytes.Equal(f.Objects, append(hx(t, "46 02 5B 01 0C 00 00 00 00 00 00 00 00 00"), le32(key)...)) {
		t.Fatalf("authentication response % X", f.Objects)
	}
}

func openFile(t *testing.T, m *dnp3.Master, c dnp3.FileCommand) dnp3.FileStatus {
	t.Helper()
	obj := c.Encode()
	f := fileRequest(t, m, dnp3.FCOpenFile, append(binary.LittleEndian.AppendUint16(hx(t, "46 03 5B 01"), uint16(len(obj))), obj...))
	st, err := dnp3.ParseFileStatus(fileObject(t, f, 4))
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func g70(v uint8, obj []byte) []byte {
	b, _ := dnp3.EncodeBlock(70, v, dnp3.QFreeFormat, []dnp3.Point{{Raw: obj}})
	return b
}

// Covers: SIG-IPE-1622
func TestOutstationFileRules(t *testing.T) {
	mem := newMemFiles()
	mem.put("cfg/a.txt", []byte("alpha"), time.Time{})
	mem.put("cfg/sub/b.txt", []byte("bravo!"), time.Time{})
	mem.put("log.txt", []byte("0123456789"), time.Time{})
	mem.dirs["empty"] = true
	o := startOutstation(t, func(c *dnp3.OutstationConfig) {
		c.Files = &dnp3.OutstationFiles{Store: mem, MaxBlock: 4, MaxOpen: 2, MaxSize: 64, Idle: 300 * time.Millisecond, Class: 3,
			Users: map[string]dnp3.FileUser{"eng": {Password: "secret", Write: true}, "op": {Password: "view"}},
			Guest: &dnp3.FileRights{Read: true}}
	})
	m := o.master(t, nil, nil)
	ctx := context.Background()
	authKey := func(user, pw string) uint32 {
		f := fileRequest(t, m, dnp3.FCAuthenticateFile, g70(2, dnp3.FileAuth{User: user, Password: pw}.Encode()))
		a, _ := dnp3.ParseFileAuth(fileObject(t, f, 2))
		return a.Key
	}
	statusOf := func(f dnp3.Fragment) uint8 {
		s, _ := dnp3.ParseFileStatus(fileObject(t, f, 4))
		return s.Status
	}

	// 5.3.1: a wrong password yields key 0; a key opens once only.
	if authKey("eng", "wrong") != 0 {
		t.Error("key for a wrong password")
	}
	if st := openFile(t, m, dnp3.FileCommand{Mode: dnp3.FileModeWrite, MaxBlock: 16, Size: 3, Permissions: 0x1FF, Name: "new.txt"}); st.Status != 1 || st.Handle != 0 {
		t.Errorf("guest write: %+v (want permission denied, handle 0)", st)
	}
	k := authKey("eng", "secret")
	if k == 0 {
		t.Fatal("no key")
	}
	st := openFile(t, m, dnp3.FileCommand{AuthKey: k, Mode: dnp3.FileModeWrite, MaxBlock: 16, Size: 3, Permissions: 0x1FF, Name: "new.txt"})
	if st.Status != 0 || st.MaxBlock != 4 {
		t.Fatalf("open with key: %+v", st)
	}
	if again := openFile(t, m, dnp3.FileCommand{AuthKey: k, Mode: dnp3.FileModeWrite, MaxBlock: 16, Name: "other.txt"}); again.Status != 1 {
		t.Errorf("a used key opened again: %+v", again)
	}
	// Rule 11 and file locking: the open file cannot be opened or deleted.
	if x := openFile(t, m, dnp3.FileCommand{Mode: dnp3.FileModeRead, MaxBlock: 16, Name: "new.txt"}); x.Status != 4 {
		t.Errorf("second open: %+v (want file locked)", x)
	}
	k = authKey("eng", "secret")
	f := fileRequest(t, m, dnp3.FCDeleteFile, g70(3, dnp3.FileCommand{AuthKey: k, Name: "new.txt"}.Encode()))
	if statusOf(f) != 4 {
		t.Errorf("delete of an open file: %d (want file locked)", statusOf(f))
	}
	// Rule 10: at most MaxOpen files at once.
	r1 := openFile(t, m, dnp3.FileCommand{Mode: dnp3.FileModeRead, MaxBlock: 16, Name: "log.txt"})
	if r1.Status != 0 || r1.Size != 10 {
		t.Fatalf("open log: %+v", r1)
	}
	if x := openFile(t, m, dnp3.FileCommand{Mode: dnp3.FileModeRead, MaxBlock: 16, Name: "cfg/a.txt"}); x.Status != 5 {
		t.Errorf("third open: %+v (want too many open)", x)
	}
	// A write block beyond the negotiated size fails and closes the file
	// (rule 14).
	obj := dnp3.FileTransport{Handle: st.Handle, Block: 0, Last: true, Data: []byte("12345")}.Encode()
	f = fileRequest(t, m, dnp3.FCWrite, g70(5, obj))
	ts, _ := dnp3.ParseFileTransportStatus(fileObject(t, f, 6))
	if ts.Status != 7 {
		t.Errorf("oversized block: %+v (want write block size)", ts)
	}
	f = fileRequest(t, m, dnp3.FCCloseFile, g70(4, dnp3.FileStatus{Handle: st.Handle}.Encode()))
	if statusOf(f) != 6 {
		t.Errorf("close after the error: %d (want invalid handle)", statusOf(f))
	}
	// A read block out of sequence fails and closes the file (rule 13).
	f = fileRequest(t, m, dnp3.FCRead, g70(5, dnp3.FileTransport{Handle: r1.Handle, Block: 1}.Encode()))
	ts, _ = dnp3.ParseFileTransportStatus(fileObject(t, f, 6))
	if ts.Status != 20 {
		t.Errorf("block out of sequence: %+v (want block sequence)", ts)
	}
	// Rule 7: more octets than announced is an error.
	k = authKey("eng", "secret")
	st = openFile(t, m, dnp3.FileCommand{AuthKey: k, Mode: dnp3.FileModeWrite, MaxBlock: 4, Size: 2, Permissions: 0x1FF, Name: "two.txt"})
	f = fileRequest(t, m, dnp3.FCWrite, g70(5, dnp3.FileTransport{Handle: st.Handle, Last: true, Data: []byte("abc")}.Encode()))
	if ts, _ = dnp3.ParseFileTransportStatus(fileObject(t, f, 6)); ts.Status == 0 {
		t.Error("a file longer than announced was accepted")
	}
	if _, ok := mem.get("two.txt"); ok {
		t.Error("a failed write was stored")
	}
	// Abort discards what was written; rule 6: a short file ends at the
	// last block.
	k = authKey("eng", "secret")
	st = openFile(t, m, dnp3.FileCommand{AuthKey: k, Mode: dnp3.FileModeWrite, MaxBlock: 4, Size: 100, Permissions: 0x1FF, Name: "abort.txt"})
	fileRequest(t, m, dnp3.FCWrite, g70(5, dnp3.FileTransport{Handle: st.Handle, Data: []byte("abcd")}.Encode()))
	f = fileRequest(t, m, dnp3.FCAbortFile, g70(4, dnp3.FileStatus{Handle: st.Handle, RequestID: 5}.Encode()))
	if statusOf(f) != 0 {
		t.Errorf("abort: %d", statusOf(f))
	}
	if _, ok := mem.get("abort.txt"); ok {
		t.Error("an aborted file was stored")
	}
	// The master's file client end to end: write, append (rule 6: a last
	// block short of the announced size ends the file), read, list, delete.
	fc := &dnp3.FileClient{M: m, MaxBlock: 4, User: "eng", Password: "secret"}
	if err := fc.WriteFile(ctx, `cfg\new.bin`, []byte("hello world")); err != nil {
		t.Fatal(err)
	}
	k = authKey("eng", "secret")
	st = openFile(t, m, dnp3.FileCommand{AuthKey: k, Mode: dnp3.FileModeAppend, MaxBlock: 4, Size: 5, Permissions: 0x1FF, Name: "cfg/new.bin"})
	fileRequest(t, m, dnp3.FCWrite, g70(5, dnp3.FileTransport{Handle: st.Handle, Last: true, Data: []byte("!")}.Encode()))
	fileRequest(t, m, dnp3.FCCloseFile, g70(4, dnp3.FileStatus{Handle: st.Handle}.Encode()))
	got, err := (&dnp3.FileClient{M: m, MaxBlock: 5}).ReadFile(ctx, "cfg/new.bin")
	if err != nil || string(got) != "hello world!" {
		t.Fatalf("read back %q %v", got, err)
	}
	// 5.3.6: a directory lists base names; sub-directories have type 0 and
	// their entry count as size; an empty directory reads as no data.
	ents, err := fc.List(ctx, `\cfg`)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name)
		if e.Name == "sub" && (e.Type != 0 || e.Size != 1) {
			t.Errorf("sub-directory entry %+v", e)
		}
		if e.Name == "a.txt" && (e.Type != 1 || e.Size != 5) {
			t.Errorf("file entry %+v", e)
		}
	}
	if strings.Join(names, ",") != "a.txt,new.bin,sub" {
		t.Errorf("entries %v", names)
	}
	if ents, err := fc.List(ctx, "empty"); err != nil || len(ents) != 0 {
		t.Errorf("empty directory: %v %v", ents, err)
	}
	if d, err := fc.Info(ctx, "cfg"); err != nil || d.Type != 0 || d.Size != 3 {
		t.Errorf("directory information %+v %v", d, err)
	}
	// IEEE 1815-2012 4.4.18: the file name of the answer is the same data
	// as in the request.
	if d, err := fc.Info(ctx, `\cfg\new.bin`); err != nil || d.Name != `\cfg\new.bin` || d.Size != 12 {
		t.Errorf("file information %+v %v", d, err)
	}
	if _, err := fc.Info(ctx, "nope"); err == nil || !strings.Contains(err.Error(), "file-not-found") {
		t.Errorf("information of a missing file: %v", err)
	}
	// Rule 15: directories are opened for reading only; rule 16: the root
	// is not deleted.
	k = authKey("eng", "secret")
	if x := openFile(t, m, dnp3.FileCommand{AuthKey: k, Mode: dnp3.FileModeWrite, MaxBlock: 4, Name: "cfg"}); x.Status == 0 {
		t.Error("a directory opened for writing")
	}
	if err := fc.Delete(ctx, `\`); err == nil {
		t.Error("the root was deleted")
	}
	// Read-only users cannot delete; writers can.
	if err := (&dnp3.FileClient{M: m, User: "op", Password: "view"}).Delete(ctx, "cfg/new.bin"); err == nil || !strings.Contains(err.Error(), "permission-denied") {
		t.Errorf("read-only delete: %v", err)
	}
	if err := fc.Delete(ctx, "cfg/new.bin"); err != nil {
		t.Fatal(err)
	}
	// Rule 12: an idle handle is closed and reported by a g70v6 event
	// (status 17) in its class.
	r2 := openFile(t, m, dnp3.FileCommand{Mode: dnp3.FileModeRead, MaxBlock: 4, Name: "cfg/a.txt"})
	if r2.Status != 0 {
		t.Fatalf("open: %+v", r2)
	}
	deadline := time.Now().Add(5 * time.Second)
	var expired bool
	for !expired && time.Now().Before(deadline) {
		time.Sleep(200 * time.Millisecond)
		frags, _ := m.Request(ctx, dnp3.FCRead, dnp3.ClassRequest(3))
		for _, fr := range frags {
			bl, _ := dnp3.ParseObjects(fr.Objects, true)
			for _, b := range bl {
				if b.Header.Group == 70 && b.Header.Var == 6 {
					ts, _ := dnp3.ParseFileTransportStatus(b.Points[0].Raw)
					expired = expired || (ts.Handle == r2.Handle && ts.Status == 17)
				}
			}
		}
	}
	if !expired {
		t.Fatal("no handle-expired event")
	}
	f = fileRequest(t, m, dnp3.FCRead, g70(5, dnp3.FileTransport{Handle: r2.Handle}.Encode()))
	if ts, _ = dnp3.ParseFileTransportStatus(fileObject(t, f, 6)); ts.Status != 6 {
		t.Errorf("read of an expired handle: %+v", ts)
	}
	// Rule 9: handles are not reused.
	r3 := openFile(t, m, dnp3.FileCommand{Mode: dnp3.FileModeRead, MaxBlock: 4, Name: "cfg/a.txt"})
	if r3.Handle == r2.Handle || r3.Handle == r1.Handle {
		t.Error("a handle was reused")
	}
}

// Covers: SIG-IPE-1623
func TestOutstationPatternControl(t *testing.T) {
	o := startOutstation(t, func(c *dnp3.OutstationConfig) { c.MaxControls = 8 })
	o.h.unknown = func(c dnp3.ControlRequest) bool { return c.Index > 12 }
	m := o.master(t, nil, nil)
	ctx := context.Background()
	pcb, _ := dnp3.EncodeBlock(12, 2, dnp3.Q8Count, []dnp3.Point{{CROB: dnp3.CROB{Code: 0x41, Count: 3, OnTime: 500, OffTime: 2000}}})
	mask := func(start, stop uint32, on ...uint32) []byte {
		var pts []dnp3.Point
		for i := start; i <= stop; i++ {
			v := false
			for _, x := range on {
				v = v || x == i
			}
			pts = append(pts, dnp3.Point{Index: i, Value: v})
		}
		b, _ := dnp3.EncodeBlock(12, 3, dnp3.Q8StartStop, pts)
		return b
	}
	// EX 4-18: points 5, 10 and 15; index 15 is beyond the configured
	// outputs: PCB status 4 with IIN2.2 and nothing operated.
	req := append(append([]byte{}, pcb...), mask(5, 15, 5, 10, 15)...)
	if !bytes.Equal(req, hx(t, "0C 02 07 01 41 03 F4 01 00 00 D0 07 00 00 00 0C 03 00 05 0F 21 04")) {
		t.Fatalf("% X", req)
	}
	frags, _ := m.Request(ctx, dnp3.FCSelect, req)
	if len(frags) != 1 || frags[0].IIN&dnp3.IINParameterError == 0 || !bytes.Equal(frags[0].Objects, hx(t, "0C 02 07 01 41 03 F4 01 00 00 D0 07 00 00 04 0C 03 00 05 0F 21 04")) {
		t.Fatalf("EX 4-18 response %+v", frags)
	}
	o.h.mu.Lock()
	n := 0
	for _, c := range o.h.controls {
		if !c.Select {
			n++
		}
	}
	o.h.mu.Unlock()
	if n != 0 {
		t.Fatal("a control was operated")
	}
	// Points 5 and 10 (two masks): select then operate operates each
	// masked point with the PCB's code.
	req = append(append(append([]byte{}, pcb...), mask(5, 7, 5)...), mask(10, 10, 10)...)
	o.h.mu.Lock()
	o.h.controls = nil
	o.h.mu.Unlock()
	err := m.SelectOperate(ctx, req, time.Second, func(fc byte, frags []dnp3.Fragment) error {
		if len(frags) != 1 || frags[0].IIN&(dnp3.IINParameterError|dnp3.IINObjectUnknown) != 0 || !bytes.Equal(frags[0].Objects, req) {
			t.Errorf("%s response %+v", dnp3.FuncName(fc), frags)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	o.h.mu.Lock()
	var operated []uint32
	for _, c := range o.h.controls {
		if !c.Select {
			if c.Group != 12 || c.Var != 2 || c.CROB.Code != 0x41 || c.CROB.Count != 3 || c.CROB.OnTime != 500 {
				t.Errorf("control %+v", c)
			}
			operated = append(operated, c.Index)
		}
	}
	o.h.mu.Unlock()
	if len(operated) != 2 || operated[0] != 5 || operated[1] != 10 {
		t.Fatalf("operated %v", operated)
	}
	// Operate without select: NO_SELECT in the PCB.
	frags, _ = m.Request(ctx, dnp3.FCOperate, req)
	if bl := blocks(t, frags[0], true); bl[0].Points[0].Status != 2 {
		t.Errorf("operate without select: %+v", bl[0].Points[0])
	}
	// More masked points than MaxControls: TOO_MANY_OBJS.
	frags, _ = m.Request(ctx, dnp3.FCDirectOperate, append(append([]byte{}, pcb...), mask(0, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8)...))
	if bl := blocks(t, frags[0], true); bl[0].Points[0].Status != 8 {
		t.Errorf("too many: %+v", bl[0].Points[0])
	}
	// A PCB without a mask, and a mask without a PCB, are malformed.
	frags, _ = m.Request(ctx, dnp3.FCDirectOperate, pcb)
	if len(frags) != 1 || frags[0].IIN&dnp3.IINParameterError == 0 {
		t.Errorf("PCB alone: %+v", frags)
	}
	frags, _ = m.Request(ctx, dnp3.FCDirectOperate, mask(0, 1, 0))
	if len(frags) != 1 || frags[0].IIN&dnp3.IINParameterError == 0 {
		t.Errorf("mask alone: %+v", frags)
	}
}

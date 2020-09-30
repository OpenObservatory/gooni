// Code generated by go-bindata. DO NOT EDIT.
// sources:
// data/default-config.json
// data/migrations/1_create_msmt_results.sql
// data/migrations/2_single_msmt_file.sql

package bindata


import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func bindataRead(data []byte, name string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewBuffer(data))
	if err != nil {
		return nil, fmt.Errorf("Read %q: %v", name, err)
	}

	var buf bytes.Buffer
	_, err = io.Copy(&buf, gz)
	clErr := gz.Close()

	if err != nil {
		return nil, fmt.Errorf("Read %q: %v", name, err)
	}
	if clErr != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}


type asset struct {
	bytes []byte
	info  fileInfoEx
}

type fileInfoEx interface {
	os.FileInfo
	MD5Checksum() string
}

type bindataFileInfo struct {
	name        string
	size        int64
	mode        os.FileMode
	modTime     time.Time
	md5checksum string
}

func (fi bindataFileInfo) Name() string {
	return fi.name
}
func (fi bindataFileInfo) Size() int64 {
	return fi.size
}
func (fi bindataFileInfo) Mode() os.FileMode {
	return fi.mode
}
func (fi bindataFileInfo) ModTime() time.Time {
	return fi.modTime
}
func (fi bindataFileInfo) MD5Checksum() string {
	return fi.md5checksum
}
func (fi bindataFileInfo) IsDir() bool {
	return false
}
func (fi bindataFileInfo) Sys() interface{} {
	return nil
}

var _bindataDataDefaultconfigJson = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\x5c\x8f\x41\x4e\xc4\x30\x0c\x45\xf7\x3d\x85\x95\x35\x9a\x81\x6d\x2f\x63\x65\x12\x0f\xb5\x94\xda\x95\xed\x0c\x42\x68\xee\x8e\x5a\xaa\x52\xd8\xfe\x97\x9f\xff\xfc\x35\x00\x24\x7c\x90\x39\xab\xa4\x11\xde\x5e\xb6\x80\xe5\xae\x36\x53\xc5\xa2\xe2\x24\x91\x46\xb8\xe7\xe6\xb4\x51\x9f\xb2\xb1\xbc\xa7\x11\xd6\x36\x40\x62\x29\xad\x57\x42\x5e\xce\xef\x4e\x20\xfb\xfa\x77\x58\xff\x0f\x8a\x76\x09\xfb\xfc\x0b\xfb\xd2\x34\x57\x34\xf2\xde\xc2\x77\x36\x00\x3c\xb7\x75\xa1\x08\xf2\x2d\xdf\xe7\x3f\xe8\xe6\x1c\xe4\xd8\xad\x61\xe3\x99\x57\xdd\xd7\xa3\x90\xeb\x23\x4b\xa1\xfa\x5b\xe8\x4e\x58\x75\xce\x2c\x78\x37\x95\xf8\x39\xe6\x2c\xee\x24\x15\x8b\x65\x9f\xd0\x68\x51\x3b\x34\x76\x5e\xb4\x35\x2a\xa1\xb6\x6e\xa6\x11\x52\xda\xc1\x4d\xbb\x14\x3a\xe2\x29\x62\xf1\xf1\x7a\xdd\xe3\x8b\xaa\xf0\x85\x35\xad\x72\xc3\x73\xf8\x0e\x00\x00\xff\xff\xfb\x1f\x97\x64\x7e\x01\x00\x00")

func bindataDataDefaultconfigJsonBytes() ([]byte, error) {
	return bindataRead(
		_bindataDataDefaultconfigJson,
		"data/default-config.json",
	)
}



func bindataDataDefaultconfigJson() (*asset, error) {
	bytes, err := bindataDataDefaultconfigJsonBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{
		name: "data/default-config.json",
		size: 0,
		md5checksum: "",
		mode: os.FileMode(0),
		modTime: time.Unix(0, 0),
	}

	a := &asset{bytes: bytes, info: info}

	return a, nil
}

var _bindataDataMigrations1createmsmtresultsSql = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xa4\x59\x6d\x73\xdb\x36\x12\xfe\xee\x5f\xb1\xe3\xe9\xf4\xec\x39\x49\x76\x72\x69\xe6\xce\xd7\x4e\xc7\xb5\x99\x9c\xda\x58\xca\xc8\xf2\x35\x99\x9b\x1b\x11\x22\x97\x12\x2a\x10\x60\xf0\x22\x46\xf7\xeb\x6f\x16\x00\x29\x52\x56\x1c\x67\xda\x0f\xa9\x48\x02\x8b\x7d\x7d\xf6\x59\x78\x38\x84\xbf\x96\x7c\xa5\x99\x45\xb8\x55\xb5\x3c\xe9\xbe\xb8\xb7\xcc\x62\x89\xd2\xfe\x82\x2b\x2e\x4f\x4e\x6e\x67\xd3\xf7\x30\xbf\xfe\xe5\x5d\x02\xa9\x46\xe3\x84\x35\xe9\x3f\x7b\x6f\x4b\x64\xc6\x69\xbf\xe7\xf0\x93\xd3\xe2\xf0\x95\x44\x5b\x2b\xbd\xa1\xd7\xc7\xcf\x4d\x64\xde\xff\xf2\x50\x3d\xa9\xe0\xcd\x2c\xb9\x9e\x27\xbd\x13\xe1\xec\x04\xfc\xcf\x05\xcf\x53\x18\x4f\xe6\xc9\xdb\x64\x06\xef\x67\xe3\xbb\xeb\xd9\x47\xf8\x2d\xf9\x08\xd7\x0f\xf3\xe9\x78\x72\x33\x4b\xee\x92\xc9\x7c\x10\x57\xa7\xf0\xef\xeb\xd9\xcd\xbf\xae\x67\x67\x2f\x7f\xf8\xe1\x1c\x26\xd3\x39\x4c\x1e\xde\xbd\x1b\xc0\x70\x08\x1f\x3e\x7c\x00\x6e\xc0\xae\xb9\x01\xa1\xe4\x0a\x50\x2a\xb7\x5a\xff\x4c\x5b\x33\x66\x71\xa5\xf4\x6e\x91\xa9\x1c\xf7\x42\x0e\x45\xcc\xd7\x08\x19\xb7\xfc\x7f\x28\x05\x5b\x42\xb3\x0b\x68\x17\x14\x4a\x83\x5d\xe3\x09\x3c\xef\xbf\xe1\x10\x0c\xb7\x38\x82\xdf\x11\x9c\x41\xda\x0a\xc6\x6a\x2e\x57\x30\x99\x4e\x12\xb0\x0a\x72\x94\xca\x7e\x8b\x40\xa9\x60\x23\x55\x2d\xfb\x9a\x8d\x4e\x1a\x5f\x66\xca\x49\xfb\xc8\xca\x97\x7b\x2b\x1b\x23\x6d\xad\x40\xa0\xb5\xa8\x21\xee\x09\x36\xd6\x6b\x9e\xad\xbd\x0b\x9f\xa7\xd5\x70\x08\x0f\xb3\x77\xb0\x44\x72\xb8\x01\xab\x4e\xce\x43\xd2\xfc\x8e\x90\x69\xa4\x64\x60\x60\xb0\x62\x3e\x2f\x2c\x5b\x8a\xe0\xc7\x26\xc5\xfc\xc3\x4b\xd0\xc8\x8c\x92\xe6\x8a\x76\xbe\x18\xc1\x1b\xa5\xc1\xa8\x12\x41\x15\xde\x6d\x5b\x8e\xb5\x81\x7a\x8d\x1a\x41\x22\xe6\xfe\xa5\x55\x96\x09\x90\xae\x5c\xa2\xa6\x85\x31\xc7\xf3\x56\xf6\x80\xa4\x71\xfb\x17\x03\x2b\x45\x5e\xb7\x0a\x96\x08\xa5\xcb\xd6\x50\x2a\x8d\x80\x45\xc1\x33\x8e\xd2\xd2\x97\x3f\x9c\xb1\x20\x94\xda\xb8\xca\x4b\xf7\x5e\x21\xb1\x5a\xd5\x06\xb8\x0c\x3e\x19\x0e\x83\x0d\x23\xfa\xf5\x72\x04\x67\xa5\x32\x16\x78\x59\x29\x6d\x99\xb4\xe7\x64\x76\xcd\x82\x44\xb6\x55\x3c\x87\xdc\x55\x82\x67\xcc\x92\x02\x0c\x96\x4e\x66\x6b\x92\xca\x65\xa1\x74\xc9\x2c\x57\x24\x99\x59\xaf\x6a\x5f\xd1\x4c\x95\x25\x7d\x55\x60\x70\x8b\x9a\x6c\x6d\x9c\x46\x0a\x3a\x83\x9a\xb6\x28\xe9\x95\x49\x3e\xb3\xb2\x12\x78\x15\x7d\x5f\xb2\x1d\xd4\xdc\xac\xbd\x22\x79\x4e\xff\xf3\x75\x11\x22\x40\xfb\x85\xca\xc2\xf1\x85\x56\x65\xe3\xe8\x4a\xab\x25\x86\x37\xf4\xf8\xf6\xfd\x3d\xc9\x53\xda\xcb\x30\xae\x22\x3b\x7d\xc8\x98\x10\xaa\xf6\xba\x36\xaa\x58\x05\xa7\x99\xd2\x1a\x33\x7b\x0a\x0c\x4a\x6e\x32\xc1\x8c\xe1\x05\xc7\x1c\x3a\xf8\x13\x05\xe6\xdc\x90\x4f\x1c\x37\x6b\x12\xb3\x44\x5b\x23\x4a\xa8\x79\xc1\x81\xc9\x1c\x4a\xb5\xe4\xe4\xe7\x3e\x74\xb4\xc8\x14\xe0\x23\x3e\x7e\x03\x84\x34\x3b\x24\x2b\xf1\x29\x2c\xb9\x0f\x85\x4a\xcb\x40\x63\xa5\xd1\xa0\xb4\x8d\xbd\x5d\x21\xb1\x62\x96\x3b\xc8\xb1\x60\x4e\x58\x8a\x49\xa5\x2a\x27\x98\xc5\x1c\x96\xcc\x60\xfe\xb5\x52\x22\x8f\x48\x2f\xf9\xfa\x7e\x32\x7a\xc6\xea\x88\x28\x9d\xca\xda\xe0\x8e\x22\xa0\xb1\x40\x8d\x32\x0b\x21\x8e\xa9\xfb\x0c\x81\xfb\xdc\x30\x03\x58\x62\xc6\x48\x7c\xdd\x4f\xa3\x53\x94\x9a\x67\xeb\xd3\xe7\x8a\xab\xb9\x8d\x85\x96\x33\xcb\x42\x09\x21\x14\xce\x3a\x8d\xa3\x6e\x2c\xec\xae\xea\xc4\xe2\xc5\xeb\x83\x50\x4c\xa5\xc7\x01\xca\x8c\x41\x4c\x0b\x8f\x77\xbc\xda\x6f\x7a\x75\xd9\xdd\x14\x02\xa8\x34\x1a\x72\x51\x88\x64\x1b\xc4\x90\xf4\xaa\x00\x26\x81\x57\xdb\x57\x94\x8c\xbc\xda\xbe\xa6\x14\xd7\x68\xcc\x73\xfc\x3f\xf7\xf5\x23\x57\x48\xc5\x5f\x51\xc4\x83\xb0\x56\x08\x08\xbe\xc1\xab\x67\x48\xba\xbc\xbc\xbc\xbc\xfa\xfa\x3f\x83\x67\x88\x0a\x89\xc8\x0d\xfc\xed\x1f\x90\xad\x99\xf6\x96\xa4\xcc\x48\x5f\x1b\x67\xaf\x3a\x1e\xea\x7a\xff\xcf\xb6\x0c\x0f\xf8\xfd\x2a\x6d\x38\x88\x2f\x52\x68\x9e\x9f\x5f\xa5\xd1\xc7\xdc\x40\xc6\x24\x41\xa1\x0a\x29\x70\x5a\xe3\x92\x5a\xaa\x39\x1d\xc0\x29\x2f\xe9\xdf\x0a\xb5\x07\x52\x99\x21\x3d\x96\x3c\xcf\x05\x2e\xd5\xe7\xd3\x10\xc6\xd4\xa2\xb1\x8b\x95\x56\xae\x3a\x28\xf9\x5e\x9a\x35\x67\xb6\x75\x95\xf3\xc2\x17\x92\x05\x63\x99\xb6\x0b\xcb\x4b\xf4\xb0\xa4\x9d\xa4\xdf\xbd\x22\x69\x01\x5f\x18\x05\x6b\xb6\xc5\x46\x9c\xcf\x7b\xab\x1a\xf4\xf3\xf9\xaf\xb6\xa8\xd7\xc8\x72\xb2\xc7\x37\xc8\xd0\x18\x34\x7a\x68\xa5\x23\x94\x5d\xa3\x86\x82\x65\x56\x69\x13\x9a\x43\x94\xb7\x52\xc0\xa5\x47\x72\x04\x32\x6c\xb4\xf7\x15\xf3\xb8\x43\xbd\x82\xed\xae\x20\xbd\x7f\xb8\x3b\x8b\xaa\x9e\xc3\x9b\xd9\xf4\x0e\x7a\x0c\x10\x6a\x2e\x04\x30\x51\xb3\x9d\x21\xff\xfe\xf8\x53\x23\x29\x8d\xbb\xc2\xa6\x7d\x20\x7d\x9f\xa3\x0f\x06\x7e\x3c\xef\x45\x75\xef\xa0\x14\x6e\xaf\xe7\xc9\x7c\x7c\x97\x1c\x78\xb6\x59\x1a\x65\xa7\x30\x4b\xae\xdf\x0d\x4e\x9a\x33\x1f\x0c\xfa\x06\xc5\x65\x4e\x9d\x12\x81\x17\xfb\xb6\xb2\x66\x06\x0c\x75\x06\x8f\x29\x41\x50\x3f\xab\xcc\x82\xe8\x01\xe6\x29\xcc\xc7\x93\x8f\x94\xea\x2f\xba\xa1\xed\xe5\x13\x55\x2a\x14\x82\xad\x48\xf8\xd1\x43\x83\x54\x5a\x98\xfb\xac\xf3\x3d\x36\x73\x9a\x92\x41\xec\x28\xfe\x92\xcb\xd5\xe8\x50\x05\x5a\xfc\x05\x05\xba\x2b\x29\x23\x16\xce\xb0\x15\x2e\x5c\x15\xfc\xf0\xf5\x95\xb9\xaa\xe5\xd1\xb5\xc3\x21\x8c\x89\xde\x50\xd7\x66\x4b\xd2\xce\xd3\xa8\xd0\xe2\x89\x36\x58\x6f\x52\xc9\x3e\xf3\xd2\x95\x20\x50\xae\xac\x87\xf2\x97\xaf\x2f\x81\x45\xa6\xec\x19\x73\x9b\xb2\x07\x6b\x55\x01\x05\x17\x08\x15\xb3\x6b\xa2\x1a\x50\x73\x99\xab\x3a\x82\x64\x77\xac\x58\xe4\x5c\x77\xe0\xe3\xf5\xe5\xa3\x18\x1c\xed\xd6\x7d\x83\x6e\xa6\x93\xfb\xf9\xec\x7a\x3c\x99\x43\x5a\x6c\x16\x9d\x0d\x11\xff\xde\x4c\x67\xc9\xf8\xed\x84\x60\xe3\xac\x2b\xef\x3c\x7e\x9f\x25\x6f\x92\x59\x32\xb9\x49\xee\x3b\x5c\xe1\x60\xe5\x63\xbc\xea\xd7\xc6\xd9\x63\xdb\xfe\x2c\x72\x5d\x35\x9f\x0a\x96\xe1\x52\xa9\xcd\xa2\x44\x63\x50\xae\x50\x37\x5f\x2c\x0a\x5c\x69\x56\x9e\xb4\x68\xce\xac\x61\x55\xd5\x3c\xaf\xad\xad\x16\x04\x1c\xa8\x17\x05\x47\x91\x2f\x4a\x26\xb9\xa7\x19\x5c\xc9\xde\x2a\x2e\xb7\x4c\xf0\x7c\xa1\xf1\x93\x23\xf8\x13\x5c\x76\x20\xc9\xac\x9b\xdf\x32\xb7\x1d\x90\xec\xc3\xe3\xeb\x57\x8f\x52\xb8\xeb\x90\xe7\x14\x7d\x77\x7d\xaf\xf2\x8f\x14\xe7\x44\xd9\x30\x17\xac\x94\x60\x72\x75\x45\xb0\xda\x54\x28\x21\x2a\xc1\xb0\xc5\x4e\x2b\x48\x43\xc1\x11\x5e\xa6\x2c\xb3\x7c\x8b\xe9\x00\x8c\x3a\xe9\x12\x10\x6e\x00\x3f\x39\xbe\x65\x22\x72\x7c\x5f\xd1\x4b\xf4\x34\x4e\x3b\x5f\xdc\x05\x13\x06\x5b\x1c\x4d\xfd\x31\x29\xcc\x93\x0f\xf3\x23\x56\x7c\xbd\xce\x63\xab\x0c\x75\xd8\x2a\xcf\x20\xc7\x80\x32\x39\x70\xb3\x70\x95\x50\x2c\xc7\xdc\x03\xd1\x00\xb8\x34\x36\x36\x04\x3f\x84\x38\xc3\xe5\xaa\x91\xd6\x2e\x5f\x14\x8c\x0b\xcc\x07\xa1\x5e\x99\x6d\xd8\x99\x54\x36\x1c\xd2\x4a\xf5\x25\xbf\xd7\x1a\x72\xd7\x46\x9f\x9a\x14\xc1\x82\xdd\x43\xd8\x81\x7d\x8d\x94\x67\x82\xe9\xe1\x59\x41\x49\xcf\x44\x9d\xf4\xd1\x69\x81\xdc\xac\x95\x13\xb9\x0f\x21\xf5\x56\xed\x97\x35\xf2\x34\x0e\x69\x03\xb7\xc7\xb5\x0a\x62\x9f\xc2\xd7\xee\x06\x5a\xed\x34\x2e\x4a\xb3\xea\x53\xfc\x06\x88\x8e\xda\xfc\x8d\x87\x74\x36\x3d\x75\x16\x41\xb4\x79\xdc\x6c\x7c\x04\x7d\x92\x56\x4c\x5b\x9e\x39\xc1\x74\xcf\x91\xd4\xf6\x96\xd4\xf6\xa2\x67\x98\xcc\xf7\xb9\x8d\x1a\x0b\x15\xf9\xc4\xc3\xd8\x43\x8d\x65\x1b\x8c\x59\x4f\x0c\x81\x65\x61\x7e\xb5\x0a\x90\x7b\x3e\xb1\xe6\x39\x02\xb7\xed\x6c\xb7\xf7\xbc\xef\x77\xd4\x42\xfd\x9c\x17\x5a\xc6\x16\xf5\x0e\x04\x32\x63\x69\x50\x6b\x67\x46\xb6\xe4\x82\xdb\x38\x69\xf4\x22\x16\xaf\x5f\x72\x45\x79\xe9\x89\x50\xc3\x8a\x62\x05\x74\x26\x13\x15\x1b\xad\x17\xd0\x31\xfa\xe7\xa3\xd1\xd1\xa8\x9d\xfc\x86\x74\x34\xa8\xb7\xa8\x87\x86\xec\x0d\xac\x6a\xc1\x73\xd0\x68\x9d\x96\x34\x90\xed\xe2\x78\x2f\x04\x12\xc3\x1a\xc1\x2f\xbb\x7e\xc9\xed\x37\x7d\x0f\x5c\x56\xce\x0e\x60\xa7\x9c\xf7\xf2\x27\x47\x7e\xf1\x9e\xa8\x38\x19\x52\xa0\x8d\xd7\x25\x5d\x43\x5a\x97\x24\x9f\xdb\x9f\x6f\x93\xb9\x47\x67\x73\x75\x71\xc1\x2a\x3e\x52\x4a\xf2\x11\x57\xf4\xfb\x62\xfb\xe2\xa2\xdb\x82\x7e\xf6\xa7\xfe\xf4\xdd\x78\xf2\xfe\x61\xfe\x7d\xab\xce\x4f\xdf\xcd\x92\xf7\xd3\xd9\x7c\x31\xbe\xdd\xcb\xb7\x9a\x65\x21\x64\x05\xd7\x34\x8d\x58\x2c\xf7\xf3\x7b\x24\x13\xff\xf9\x6f\x0a\x82\x1b\xdb\x14\xa4\x0c\x7a\xb7\x5d\xa9\x9f\xd8\x5a\xa4\x64\xda\x2a\xb2\x87\x5f\xef\xa7\x93\x70\x3d\xd0\x37\x92\xa6\xcb\x0e\x01\x45\x13\x26\x84\x2d\x13\x0e\x0d\x9c\xa5\xad\xde\xe9\x00\x52\x6f\x51\x7a\x0e\x4c\x7b\x34\x28\x9c\xd8\x7b\x8f\xb5\xdc\xa3\x23\xdc\x17\x08\x15\x01\x13\x1a\x59\xbe\x0b\xc5\x50\x69\x95\x51\xe3\x6c\xc3\x58\xf1\x0a\xa9\xbd\x0d\x3a\x58\xc2\xcb\x4a\x04\x21\x99\x40\x26\x5d\xe5\x87\xbd\x28\xa6\x45\xc9\xae\xc3\x5b\x36\xd7\x68\xdc\xaf\xe4\xc3\x9e\xee\x87\xa2\x9a\xdc\x28\x55\x43\xdc\x3d\x4b\x6a\x8a\xf6\x2b\xc3\xda\x70\x18\xaf\xc6\xf2\x51\x04\xa4\x83\x6b\xd0\xc7\x89\x4d\x28\xbf\x43\x4b\xe4\x15\x19\x0d\xd0\xcd\x85\x4d\x9b\xc7\x03\x58\x3a\xdf\x14\xc8\xc5\x95\x60\x9e\xa6\xc6\xdb\x9f\x5e\x57\x64\x36\x5c\xad\x55\x8a\x4b\xdb\x4c\xe5\x12\x99\xee\x8c\xe6\x61\x82\x46\xbc\x6a\x53\x76\xc5\xed\xda\x2d\x47\x99\x2a\x2f\x28\x73\x2f\x1a\xc7\x5f\x2c\x85\x5a\x5e\x94\xcc\x58\xd4\x17\xb9\xca\x8c\xff\x3c\x74\x8e\xe7\xa3\x32\x87\xef\xbb\xc4\xe4\x49\x39\xdc\x18\x87\xe6\xe2\xd5\xdf\x83\x47\x5a\xbb\x16\x47\x78\x18\xb1\x93\x43\x1f\x45\x64\x35\x8d\x45\x19\x33\xde\x49\x0c\x9a\xa1\xd1\x8f\x4c\x83\x90\x59\xcc\x5f\xcd\x92\x67\x69\x50\x17\xbb\x46\xd6\x52\xa8\x6c\x43\x5d\x96\xa8\x01\xc1\xa1\x84\xf1\x9d\xdf\xd8\xcc\x07\xf1\xd1\xd0\xa0\x65\x22\x14\x54\x4f\x0b\xe2\x85\xbf\x0f\x8b\x93\x29\xd4\xcc\x40\x8e\x16\x33\x9f\x00\x71\xfd\xc7\x88\x30\xe9\xaf\xd3\xf1\x24\x05\x06\xe9\xcd\xf4\x61\x32\x3f\x3b\x4f\xdb\xda\xf3\x95\xd5\x98\x17\x27\xb3\x80\xdb\xb1\x5a\x59\x7b\x69\x79\xa0\x05\x04\xfb\x95\x6e\x5f\x8c\xef\x48\xed\x70\xc7\x9b\x72\xb3\x60\x52\x95\x4c\xec\xba\x30\x7b\x64\x72\x92\xa0\x2a\xf6\xc9\x45\x4c\x30\x56\xbb\x8c\x32\x66\x10\x6f\x66\x6b\xa2\x69\xd4\x97\xba\x57\xb7\x9e\x5b\x6e\x70\x67\x5a\x62\x1b\xaf\x70\xe3\x6d\x7a\x9f\xaa\xa0\x65\x5c\x98\x78\xdf\x4b\x68\xe5\x45\x75\x7a\x94\x81\x33\xfc\x3c\xea\x36\xb0\x50\xd1\x17\x34\x24\xd1\x0f\x30\x15\x49\x57\x05\x4c\x6e\xe7\x83\xe8\x2b\xcf\xc6\x8a\xc6\x7e\x2a\x0c\x9f\x19\xe4\x96\x96\xb7\xa1\xcd\x46\xe7\x1d\x3e\x4c\x3a\xa7\xc1\xd2\x63\x0d\x07\x21\xd3\xca\x34\x17\xaa\xbd\xee\x46\x21\x0c\xb6\xd7\x2a\x5e\xaa\x81\x55\x2b\xa4\x3e\x3c\xfa\xe2\x8d\x48\xe7\x90\xc7\x23\xeb\x96\x69\xee\x0f\xf2\x4c\x82\x4b\x8b\x5a\x32\x21\x7c\x27\xa6\x16\xb0\x09\x68\xc8\xc2\x78\xe7\xef\x19\xe4\x30\xe7\x66\x73\x04\x5b\xcd\xe8\x0f\xa3\xe4\x08\xc6\xd6\x13\xc8\x92\x98\x83\x41\x69\xbc\xee\xb5\xa6\xba\x20\x9e\x1c\xe6\x3e\xd4\x80\xfe\xaa\x67\xd9\xa6\xf6\x5a\x29\xef\xc2\xbb\xdf\x7c\x84\x2a\x8d\xdb\x78\x37\xda\xd0\x0b\x12\xd2\xa0\x4f\x90\xa3\x24\xf1\x88\x4d\xbc\xa3\x2a\xd9\x5e\x18\xb1\x83\x92\xc9\x5d\x4f\x43\x7f\x6e\xe1\xef\x7f\xbb\xc8\x4c\x6f\x16\x64\xe4\xd3\x83\xe6\xc1\x14\xb9\xf7\xf5\xe3\x21\xd2\xf7\xa9\xe6\xf3\xb1\x21\xb2\xb9\x01\x39\xb6\x6e\x3a\x81\xdb\xe4\x5d\x32\x4f\xe0\xe6\xfa\xfe\xe6\xfa\x36\xf1\x9d\x62\x5c\x50\x8a\xe7\x28\xd0\x06\xde\xe3\x73\xb7\xcb\x8a\xbe\xdc\x1e\x86\x43\x60\x42\x1c\x96\x85\x89\x7f\x10\x08\x32\x73\x9a\xdc\x6b\x14\x22\xf8\xa6\x6f\x4c\x6c\x24\xe7\x3d\x1b\xfc\xdf\xdb\xf6\xdf\x68\x00\xfe\xe2\x5f\xf5\xfe\x1f\x00\x00\xff\xff\x38\xc6\x64\x22\x78\x1c\x00\x00")

func bindataDataMigrations1createmsmtresultsSqlBytes() ([]byte, error) {
	return bindataRead(
		_bindataDataMigrations1createmsmtresultsSql,
		"data/migrations/1_create_msmt_results.sql",
	)
}



func bindataDataMigrations1createmsmtresultsSql() (*asset, error) {
	bytes, err := bindataDataMigrations1createmsmtresultsSqlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{
		name: "data/migrations/1_create_msmt_results.sql",
		size: 0,
		md5checksum: "",
		mode: os.FileMode(0),
		modTime: time.Unix(0, 0),
	}

	a := &asset{bytes: bytes, info: info}

	return a, nil
}

var _bindataDataMigrations2singlemsmtfileSql = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xec\x56\x4d\x6f\xdb\x38\x10\xbd\xf3\x57\xcc\xd1\xc6\x2a\x8b\xdd\xb6\xc9\xc5\xe8\x81\x91\x99\x54\xad\x4c\xa5\x14\x53\x34\x27\x89\xb5\x68\x47\x88\x4c\x0a\x24\xd5\x20\xff\xbe\x90\x3f\x6a\xda\x96\x8d\x3a\x28\x8a\x1e\x74\x9d\x8f\xc7\x21\xe7\x0d\xe7\x5d\x5c\xc0\x3f\x8b\x72\x6e\x84\x93\x30\xd6\xcf\x0a\xf9\x86\xd4\x09\x27\x17\x52\xb9\x6b\x39\x2f\x15\x42\x77\x0c\xdf\x4e\x30\xcc\xb4\x91\xe5\x5c\x65\x4f\xf2\xc5\xbe\xd7\xb3\xd9\x08\xe1\x98\x13\x06\x1c\x5f\xc7\x04\xf2\x85\x14\xb6\x31\xcb\x3c\x9b\x03\x23\x14\x4f\x08\xf0\x04\xf2\xcc\xf7\x64\x4a\x3e\xe7\x23\x84\x42\x46\x30\x27\xdd\xb9\x03\x04\x00\x3b\xc6\xac\x2c\x72\x88\x28\x27\xb7\x84\xc1\x1d\x8b\x26\x98\x3d\xc0\x27\xf2\x00\xf8\x9e\x27\x11\x0d\x19\x99\x10\xca\x83\x55\x9e\x93\xd6\x65\x4a\x2c\x64\x0e\x5f\x30\x0b\x3f\x60\x36\xb8\x7a\x37\x04\x9a\x70\xa0\xf7\x71\x1c\x1c\xa2\x5b\x27\x8c\xcb\x5c\xd9\xa6\x8c\x31\x27\x3c\x9a\x90\x53\xf1\xa6\x51\xab\x60\x46\x70\xec\x05\x76\xd4\x6d\xb3\x42\x2b\x99\x03\x8f\xe8\x43\x44\xf9\xe0\xff\x93\x85\x94\x36\x6b\xea\x4a\x8b\x42\x16\x67\xa4\xcc\x44\x59\xfd\x7a\x42\x1b\xdd\x18\x99\x2d\xec\x7c\xfb\x40\x6f\x2e\x2f\x87\xa7\xea\x39\xf3\x0c\x2f\xe9\x8c\xa3\x8c\x34\x8d\x3a\x75\x84\x91\xb5\x36\x2b\x32\x74\xa0\x35\xa6\xf2\x79\xb2\xb6\x4e\x75\x55\xc9\xa9\xd3\x26\xeb\xe0\x53\x4b\x8c\x75\x5c\x69\x33\xa1\xf4\x42\x54\x2f\x7e\x05\x3e\xa5\x5a\xde\xe7\xf0\x31\x4d\xe8\x61\x5d\xb6\xa9\x76\x49\xda\x5d\xf9\xac\xac\x64\x56\x0b\xf7\xe8\x5d\xe0\xea\xbf\xfd\x7b\x86\x09\x4d\x39\xc3\x11\xe5\x90\xcf\x9e\xb2\x2d\xfa\xd2\x0b\x70\x93\x30\x12\xdd\xd2\xe5\x00\x0c\xbc\xc3\x87\x6b\x3f\x23\x37\x84\x11\x1a\x92\x74\x53\x9a\xcd\xbb\xe2\x12\x0a\x63\x12\x13\x4e\x20\xc4\x69\x88\xc7\x64\x75\xfc\x2e\xfc\xfa\x55\x87\x3b\xa8\x8d\xa9\x5a\xc8\x8d\x0f\x0d\x47\x08\x45\x34\x25\x8c\xb7\x0f\x90\x80\x3f\xcf\x30\x40\xfb\xa3\x1c\x20\x6f\x48\x03\x74\x6c\x16\xf7\x3c\x9b\xa9\xdb\x33\x6f\x46\xec\xd0\xfc\x73\x94\x0e\x5d\x6b\x3a\xef\x39\x7c\xbe\x1e\x83\x3b\x92\xda\xc1\xf8\x43\x84\x15\xc1\x03\xe4\x11\x39\x40\x9b\x57\x0c\xd0\x71\xae\x06\xc8\xe7\xe7\xe6\xf9\x96\x84\x5c\xa2\x6d\x3a\xbb\x85\xde\x32\x0d\xb5\xed\x4e\x49\x4c\x42\x7e\xf0\xa7\xf6\x8d\xf8\x93\x8d\x00\xb8\x61\xc9\x04\x0e\xf6\xe1\x08\xa1\x31\x4b\xee\xd6\xcb\xb0\xcb\xdd\xb9\x81\xd5\x08\x75\xaf\x6d\xa2\x8a\x5d\xcf\x7d\xfd\xba\xfd\xde\x66\xa5\x9f\xe3\xd2\xc9\xb7\x50\x68\x69\x41\x69\x07\xb6\xa9\xdb\x8b\x81\x28\x8a\x52\xcd\x61\xaa\xab\x66\xa1\x2c\x68\x03\x85\xd1\x75\xbd\xb2\x29\xeb\x8c\x28\x95\xb3\x01\x58\x0d\xcf\x12\x94\x94\x45\x0b\xe7\x34\x18\x79\x31\x35\xb2\x2d\xc4\x3d\x4a\x70\xe2\x5b\x25\x41\xa8\x02\xa6\xba\x7e\x59\x9a\x0a\xe1\x04\xe8\xef\xd2\xfc\x8b\x5e\x25\x31\x74\x55\xf4\x12\xa3\x97\x18\xbd\xc4\xf0\x24\x46\x57\x97\xb6\x91\x9c\x7c\xe5\xbd\xf6\xe8\x57\xde\xef\x5e\x79\xfb\x77\xec\x45\xc9\xdf\xd7\xa1\xf6\x0b\xe9\x96\x26\xba\x2a\x4e\x49\x93\x95\xfb\x7c\x69\xf2\x23\x00\x00\xff\xff\xca\xeb\xb6\x24\x7c\x10\x00\x00")

func bindataDataMigrations2singlemsmtfileSqlBytes() ([]byte, error) {
	return bindataRead(
		_bindataDataMigrations2singlemsmtfileSql,
		"data/migrations/2_single_msmt_file.sql",
	)
}



func bindataDataMigrations2singlemsmtfileSql() (*asset, error) {
	bytes, err := bindataDataMigrations2singlemsmtfileSqlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{
		name: "data/migrations/2_single_msmt_file.sql",
		size: 0,
		md5checksum: "",
		mode: os.FileMode(0),
		modTime: time.Unix(0, 0),
	}

	a := &asset{bytes: bytes, info: info}

	return a, nil
}


//
// Asset loads and returns the asset for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
//
func Asset(name string) ([]byte, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("Asset %s can't read by error: %v", name, err)
		}
		return a.bytes, nil
	}
	return nil, &os.PathError{Op: "open", Path: name, Err: os.ErrNotExist}
}

//
// MustAsset is like Asset but panics when Asset would return an error.
// It simplifies safe initialization of global variables.
// nolint: deadcode
//
func MustAsset(name string) []byte {
	a, err := Asset(name)
	if err != nil {
		panic("asset: Asset(" + name + "): " + err.Error())
	}

	return a
}

//
// AssetInfo loads and returns the asset info for the given name.
// It returns an error if the asset could not be found or could not be loaded.
//
func AssetInfo(name string) (os.FileInfo, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("AssetInfo %s can't read by error: %v", name, err)
		}
		return a.info, nil
	}
	return nil, &os.PathError{Op: "open", Path: name, Err: os.ErrNotExist}
}

//
// AssetNames returns the names of the assets.
// nolint: deadcode
//
func AssetNames() []string {
	names := make([]string, 0, len(_bindata))
	for name := range _bindata {
		names = append(names, name)
	}
	return names
}

//
// _bindata is a table, holding each asset generator, mapped to its name.
//
var _bindata = map[string]func() (*asset, error){
	"data/default-config.json":                  bindataDataDefaultconfigJson,
	"data/migrations/1_create_msmt_results.sql": bindataDataMigrations1createmsmtresultsSql,
	"data/migrations/2_single_msmt_file.sql":    bindataDataMigrations2singlemsmtfileSql,
}

//
// AssetDir returns the file names below a certain
// directory embedded in the file by go-bindata.
// For example if you run go-bindata on data/... and data contains the
// following hierarchy:
//     data/
//       foo.txt
//       img/
//         a.png
//         b.png
// then AssetDir("data") would return []string{"foo.txt", "img"}
// AssetDir("data/img") would return []string{"a.png", "b.png"}
// AssetDir("foo.txt") and AssetDir("notexist") would return an error
// AssetDir("") will return []string{"data"}.
//
func AssetDir(name string) ([]string, error) {
	node := _bintree
	if len(name) != 0 {
		cannonicalName := strings.Replace(name, "\\", "/", -1)
		pathList := strings.Split(cannonicalName, "/")
		for _, p := range pathList {
			node = node.Children[p]
			if node == nil {
				return nil, &os.PathError{
					Op: "open",
					Path: name,
					Err: os.ErrNotExist,
				}
			}
		}
	}
	if node.Func != nil {
		return nil, &os.PathError{
			Op: "open",
			Path: name,
			Err: os.ErrNotExist,
		}
	}
	rv := make([]string, 0, len(node.Children))
	for childName := range node.Children {
		rv = append(rv, childName)
	}
	return rv, nil
}


type bintree struct {
	Func     func() (*asset, error)
	Children map[string]*bintree
}

var _bintree = &bintree{Func: nil, Children: map[string]*bintree{
	"data": {Func: nil, Children: map[string]*bintree{
		"default-config.json": {Func: bindataDataDefaultconfigJson, Children: map[string]*bintree{}},
		"migrations": {Func: nil, Children: map[string]*bintree{
			"1_create_msmt_results.sql": {Func: bindataDataMigrations1createmsmtresultsSql, Children: map[string]*bintree{}},
			"2_single_msmt_file.sql": {Func: bindataDataMigrations2singlemsmtfileSql, Children: map[string]*bintree{}},
		}},
	}},
}}

// RestoreAsset restores an asset under the given directory
func RestoreAsset(dir, name string) error {
	data, err := Asset(name)
	if err != nil {
		return err
	}
	info, err := AssetInfo(name)
	if err != nil {
		return err
	}
	err = os.MkdirAll(_filePath(dir, filepath.Dir(name)), os.FileMode(0755))
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(_filePath(dir, name), data, info.Mode())
	if err != nil {
		return err
	}
	return os.Chtimes(_filePath(dir, name), info.ModTime(), info.ModTime())
}

// RestoreAssets restores an asset under the given directory recursively
func RestoreAssets(dir, name string) error {
	children, err := AssetDir(name)
	// File
	if err != nil {
		return RestoreAsset(dir, name)
	}
	// Dir
	for _, child := range children {
		err = RestoreAssets(dir, filepath.Join(name, child))
		if err != nil {
			return err
		}
	}
	return nil
}

func _filePath(dir, name string) string {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	return filepath.Join(append([]string{dir}, strings.Split(cannonicalName, "/")...)...)
}

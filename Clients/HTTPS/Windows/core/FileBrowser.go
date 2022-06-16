package core

import (
	"io/ioutil"
	"os/user"
)

func ExploreDirectory(path string) (*FileExplorer, error) {
	if len(path) == 0 {
		usr, err := user.Current()
		if err != nil {
			return nil, err
		}
		path = usr.HomeDir
	}
	return ListDirectory(path)
}

func ListDirectory(path string) (*FileExplorer, error) {
	dirFiles, err := ioutil.ReadDir(path)
	if err != nil {
		return nil, err
	}

	var files []File
	var directories []string
	for _, f := range dirFiles {
		if f.IsDir() {
			directories = append(directories, f.Name())
			continue
		}
		files = append(files, File{
			Filename: f.Name(),
			ModTime:  f.ModTime(),
		})
	}

	return &FileExplorer{
		Path:        path,
		Files:       files,
		Directories: directories,
	}, nil
}

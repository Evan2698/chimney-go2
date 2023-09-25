package utils

import (
	"log"
	"os"
	"os/exec"
	"path/filepath"
)

func RetrieveExePath() (string, error) {
	file, err := exec.LookPath(os.Args[0])
	if err != nil {
		return "", err
	}
	re, err := filepath.Abs(file)
	if err != nil {
		log.Print("The eacePath failed:", err.Error())
	}
	log.Print("The path is ", re)
	return filepath.Dir(re), err
}

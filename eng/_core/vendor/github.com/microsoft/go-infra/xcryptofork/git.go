package xcryptofork

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
)

func GitCheckoutTo(gitDir, outDir string) error {
	outDir, err := filepath.Abs(outDir)
	if err != nil {
		return err
	}
	cmd := exec.Command(
		"git",
		"checkout-index",
		"--all",
		"-f",
		"--prefix="+outDir+"/",
	)
	cmd.Dir = gitDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	log.Printf("In %#q, running %v", cmd.Dir, cmd)
	return cmd.Run()
}

func RemoveDirContent(dir string, prompt bool) error {
	if prompt {
		fmt.Printf("Delete %#q? [y/N] ", dir)
		s := bufio.NewScanner(os.Stdin)
		_ = s.Scan()
		if s.Text() != "y" {
			return fmt.Errorf("aborting: %q not %q\n", s.Text(), "y")
		}
		if err := s.Err(); err != nil {
			return err
		}
		fmt.Println()
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// Nothing to do.
			return nil
		}
		return err
	}
	for _, entry := range entries {
		if err := os.RemoveAll(filepath.Join(dir, entry.Name())); err != nil {
			return err
		}
	}
	return nil
}

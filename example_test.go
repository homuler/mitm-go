package mitm_test

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/homuler/mitm-proxy-go"
)

func Example_memorizingReader_Memorized() {
	mr := mitm.NewMemorizingReader(strings.NewReader("Hello, World!"), nil)
	io.ReadAll(mr)
	mr.Seek(0, io.SeekStart)
	fmt.Println(string(mr.Memorized()))
	// Output: Hello, World!
}

func Example_memorizingReader_OneTimeReader() {
	mr := mitm.NewMemorizingReader(strings.NewReader("Hello, World!"), nil)
	bs, err := mr.Next(5)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(bs))

	// read from the beginning again without memorizing.
	if _, err = mr.Seek(0, io.SeekStart); err != nil {
		log.Fatal(err)
	}
	if _, err := io.Copy(os.Stdout, mr.OneTimeReader()); err != nil {
		log.Fatal(err)
	}
	// Output:
	// Hello
	// Hello, World!
}

package main

import (
	"fmt"
	"github.com/eopenio/slowlog-parser/log"
	"github.com/eopenio/slowlog-parser/parser"
)

func main()  {
	var opt log.Options
	SlowLogParser := parser.NewSlowLogParser(opt)
    text:= ""
	event,err:= SlowLogParser.Parser(text)
	if err != nil{
		return
	}
	fmt.Printf("具体SQL:%#v \n", event.Query)
	fmt.Printf("SQL样例:%#v  \n", SlowLogParser.Fingerprint())
	fmt.Printf("SQLID:%#v \n", SlowLogParser.Id())

    //// open file
	//f, err := os.Open("./20271_202210191404_mysql-slow.log")
	//if err != nil {
	//	return
	//}
	//// remember to close the file at the end of the program
	//defer f.Close()
	//
	//// read the file line by line using scanner
	//scanner := bufio.NewScanner(f)
	//
	//for scanner.Scan() {
	//	// do something with a line
	//	//fmt.Printf("line: %s\n", scanner.Text())
	//	event,err:= SlowLogParser.Parser(scanner.Text())
	//	if err != nil{
	//		return
	//	}
	//	fmt.Println(event.Query)
	//	fmt.Println(SlowLogParser.Fingerprint())
	//	fmt.Println(SlowLogParser.Id())
	//}
	//
	//if err := scanner.Err(); err != nil {
	//	return
	//}


}



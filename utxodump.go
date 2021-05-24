package main

// local packages
import (
    "github.com/in3rsha/bitcoin-utxo-dump/bitcoin/btcleveldb"
    "github.com/panjf2000/ants"
    "sync"
)                                         // chainstate leveldb decoding functions
import "github.com/in3rsha/bitcoin-utxo-dump/bitcoin/keys"   // bitcoin addresses
import "github.com/in3rsha/bitcoin-utxo-dump/bitcoin/bech32" // segwit bitcoin addresses

import "github.com/syndtr/goleveldb/leveldb" // go get github.com/syndtr/goleveldb/leveldb
import "github.com/syndtr/goleveldb/leveldb/opt" // set no compression when opening leveldb
import "flag"         // command line arguments
import "fmt"
import "os"           // open file for writing

import "os/signal"    // catch interrupt signals CTRL-C to close db connection safely
import "syscall"      // catch kill commands too
import "bufio"        // bulk writing to file
import "encoding/hex" // convert byte slice to hexadecimal
import "strings"      // parsing flags from command line
import "runtime"      // Check OS type for file-handler limitations


func parse(i interface{}){
    var output = map[string]string{}

    utxo := i.(map[string][]byte)

    key := utxo["key"]
    value := utxo["value"]
    obfuscateKey := utxo["obfuscateKey"]
    // first byte in key indicates the type of key we've got for leveldb
    prefix := key[0]

    // utxo entry
    if (prefix == 67) { // 67 = 0x43 = C = "utxo"

        // ---
        // Key
        // ---

        //      430000155b9869d56c66d9e86e3c01de38e3892a42b99949fe109ac034fff6583900
        //      <><--------------------------------------------------------------><>
        //      /                               |                                  \
        //  type                          txid (little-endian)                      index (varint)

        // txid
        if fieldsSelected["txid"] {
            txidLE := key[1:33] // little-endian byte order

            // txid - reverse byte order
            txid := make([]byte, 0) // create empty byte slice (dont want to mess with txid directly)
            for i := len(txidLE)-1; i >= 0; i-- { // run backwards through the txid slice
                txid = append(txid, txidLE[i]) // append each byte to the new byte slice
            }
            output["txid"] = hex.EncodeToString(txid) // add to output results map
        }

        // vout
        if fieldsSelected["vout"] {
            index := key[33:]

            // convert varint128 index to an integer
            vout := btcleveldb.Varint128Decode(index)
            output["vout"] = fmt.Sprintf("%d",vout)
        }

        // -----
        // Value
        // -----

        // Only deobfuscate and get data from the Value if something is needed from it (improves speed if you just want the txid:vout)
        if fieldsSelected["type"] || fieldsSelected["height"] || fieldsSelected["coinbase"] || fieldsSelected["amount"] || fieldsSelected["nsize"] || fieldsSelected["script"] || fieldsSelected["type"] || fieldsSelected["address"] {

            // Copy the obfuscateKey ready to extend it
            obfuscateKeyExtended := obfuscateKey[1:] // ignore the first byte, as that just tells you the size of the obfuscateKey

            // Extend the obfuscateKey so it's the same length as the value
            for i, k := len(obfuscateKeyExtended), 0; len(obfuscateKeyExtended) < len(value); i, k = i+1, k+1 {
                // append each byte of obfuscateKey to the end until it's the same length as the value
                obfuscateKeyExtended = append(obfuscateKeyExtended, obfuscateKeyExtended[k])
                // Example
                //   [8 175 184 95 99 240 37 253 115 181 161 4 33 81 167 111 145 131 0 233 37 232 118 180 123 120 78]
                //   [8 177 45 206 253 143 135 37 54]                                                                  <- obfuscate key
                //   [8 177 45 206 253 143 135 37 54 8 177 45 206 253 143 135 37 54 8 177 45 206 253 143 135 37 54]    <- extended
            }

            // XOR the value with the obfuscateKey (xor each byte) to de-obfuscate the value
            var xor []byte // create a byte slice to hold the xor results
            for i := range value {
                result := value[i] ^ obfuscateKeyExtended[i]
                xor = append(xor, result)
            }

            // -----
            // Value
            // -----

            //   value: 71a9e87d62de25953e189f706bcf59263f15de1bf6c893bda9b045 <- obfuscated
            //          b12dcefd8f872536b12dcefd8f872536b12dcefd8f872536b12dce <- extended obfuscateKey (XOR)
            //          c0842680ed5900a38f35518de4487c108e3810e6794fb68b189d8b <- deobfuscated
            //          <----><----><><-------------------------------------->
            //           /      |    \                   |
            //      varint   varint   varint          script <- P2PKH/P2SH hash160, P2PK public key, or complete script
            //         |        |     nSize
            //         |        |
            //         |     amount (compressesed)
            //         |
            //         |
            //  100000100001010100110
            //  <------------------> \
            //         height         coinbase

            offset := 0

            // First Varint
            // ------------
            // b98276a2ec7700cbc2986ff9aed6825920aece14aa6f5382ca5580
            // <---->
            varint, bytesRead := btcleveldb.Varint128Read(xor, 0) // start reading at 0
            offset += bytesRead
            varintDecoded := btcleveldb.Varint128Decode(varint)

            if fieldsSelected["height"] || fieldsSelected["coinbase"] {

                // Height (first bits)
                height := varintDecoded >> 1 // right-shift to remove last bit
                output["height"] = fmt.Sprintf("%d", height)

                // Coinbase (last bit)
                coinbase := varintDecoded & 1 // AND to extract right-most bit
                output["coinbase"] = fmt.Sprintf("%d", coinbase)
            }

            // Second Varint
            // -------------
            // b98276a2ec7700cbc2986ff9aed6825920aece14aa6f5382ca5580
            //       <---->
            varint, bytesRead = btcleveldb.Varint128Read(xor, offset) // start after last varint
            offset += bytesRead
            varintDecoded = btcleveldb.Varint128Decode(varint)

            // Amount
            if fieldsSelected["amount"] {
                amount := btcleveldb.DecompressValue(varintDecoded) // int64
                output["amount"] = fmt.Sprintf("%d", amount)
                //totalAmount += amount // add to stats
            }

            // Third Varint
            // ------------
            // b98276a2ec7700cbc2986ff9aed6825920aece14aa6f5382ca5580
            //             <>
            //
            // nSize - byte to indicate the type or size of script - helps with compression of the script data
            //  - https://github.com/bitcoin/bitcoin/blob/master/src/compressor.cpp

            //  0  = P2PKH <- hash160 public key
            //  1  = P2SH  <- hash160 script
            //  2  = P2PK 02publickey <- nsize makes up part of the public key in the actual script
            //  3  = P2PK 03publickey
            //  4  = P2PK 04publickey (uncompressed - but has been compressed in to leveldb) y=even
            //  5  = P2PK 04publickey (uncompressed - but has been compressed in to leveldb) y=odd
            //  6+ = [size of the upcoming script] (subtract 6 though to get the actual size in bytes, to account for the previous 5 script types already taken)
            varint, bytesRead = btcleveldb.Varint128Read(xor, offset) // start after last varint
            offset += bytesRead
            nsize := btcleveldb.Varint128Decode(varint) //
            output["nsize"] = fmt.Sprintf("%d", nsize)

            // Script (remaining bytes)
            // ------
            // b98276a2ec7700cbc2986ff9aed6825920aece14aa6f5382ca5580
            //               <-------------------------------------->
            if nsize > 1 && nsize < 6 { // either 2, 3, 4, 5
                // move offset back a byte if script type is 2, 3, 4, or 5 (because this forms part of the P2PK public key along with the actual script)
                offset--
            }

            script := xor[offset:]
            if fieldsSelected["script"] {
                output["script"] = hex.EncodeToString(script)
            }

            // Addresses - Get address from script (if possible), and set script type (P2PK, P2PKH, P2SH, P2MS, P2WPKH, or P2WSH)
            // ---------
            if fieldsSelected["address"] || fieldsSelected["type"] {

                var address string // initialize address variable
                var scriptType string = "non-standard" // initialize script type

                // P2PKH
                if nsize == 0 {
                    if fieldsSelected["address"] { // only work out addresses if they're wanted
                        if testnet == true {
                            address = keys.Hash160ToAddress(script, []byte{0x6f}) // (m/n)address - testnet addresses have a special prefix
                        } else {
                            address = keys.Hash160ToAddress(script, []byte{0x00}) // 1address
                        }
                    }
                    scriptType = "p2pkh"
                    //scriptTypeCount["p2pkh"] += 1
                }

                // P2SH
                if nsize == 1 {
                    if fieldsSelected["address"] { // only work out addresses if they're wanted
                        if testnet == true {
                            address = keys.Hash160ToAddress(script, []byte{0xc4}) // 2address - testnet addresses have a special prefix
                        } else {
                            address = keys.Hash160ToAddress(script, []byte{0x05}) // 3address
                        }
                    }
                    scriptType = "p2sh"
                    //scriptTypeCount["p2sh"] += 1
                }

                // P2PK
                if 1 < nsize && nsize < 6 { // 2, 3, 4, 5
                    //  2 = P2PK 02publickey <- nsize makes up part of the public key in the actual script (e.g. 02publickey)
                    //  3 = P2PK 03publickey <- y is odd/even (0x02 = even, 0x03 = odd)
                    //  4 = P2PK 04publickey (uncompressed)  y = odd  <- actual script uses an uncompressed public key, but it is compressed when stored in this db
                    //  5 = P2PK 04publickey (uncompressed) y = even

                    // "The uncompressed pubkeys are compressed when they are added to the db. 0x04 and 0x05 are used to indicate that the key is supposed to be uncompressed and those indicate whether the y value is even or odd so that the full uncompressed key can be retrieved."
                    //
                    // if nsize is 4 or 5, you will need to uncompress the public key to get it's full form
                    // if nsize == 4 || nsize == 5 {
                    //     // uncompress (4 = y is even, 5 = y is odd)
                    //     script = decompress(script)
                    // }

                    scriptType = "p2pk"
                    //scriptTypeCount["p2pk"] += 1

                    if fieldsSelected["address"] { // only work out addresses if they're wanted
                        if p2pkaddresses { // if we want to convert public keys in P2PK scripts to their corresponding addresses (even though they technically don't have addresses)

                            // Decompress if starts with 0x04 or 0x05
                            if (nsize == 4) || (nsize == 5) {
                                script = keys.DecompressPublicKey(script)
                            }

                            if testnet == true {
                                address = keys.PublicKeyToAddress(script, []byte{0x6f}) // (m/n)address - testnet addresses have a special prefix
                            } else {
                                address = keys.PublicKeyToAddress(script, []byte{0x00}) // 1address
                            }
                        }
                    }
                }

                // P2MS
                if len(script) > 0 && script[len(script)-1] == 174 { // if there is a script and if the last opcode is OP_CHECKMULTISIG (174) (0xae)
                    scriptType = "p2ms"
                    //scriptTypeCount["p2ms"] += 1
                }

                // P2WPKH
                if nsize == 28 && script[0] == 0 && script[1] == 20 { // P2WPKH (script type is 28, which means length of script is 22 bytes)
                    // 315,c016e8dcc608c638196ca97572e04c6c52ccb03a35824185572fe50215b80000,0,551005,3118,0,28,001427dab16cca30628d395ccd2ae417dc1fe8dfa03e
                    // script  = 0014700d1635c4399d35061c1dabcc4632c30fedadd6
                    // script  = [0 20 112 13 22 53 196 57 157 53 6 28 29 171 204 70 50 195 15 237 173 214]
                    // version = [0]
                    // program =      [112 13 22 53 196 57 157 53 6 28 29 171 204 70 50 195 15 237 173 214]
                    version := script[0]
                    program := script[2:]

                    // bech32 function takes an int array and not a byte array, so convert the array to integers
                    var programint []int // initialize empty integer array to hold the new one
                    for _, v := range program {
                        programint = append(programint, int(v)) // cast every value to an int
                    }

                    if fieldsSelected["address"] { // only work out addresses if they're wanted
                        if testnet == true {
                            address, _ = bech32.SegwitAddrEncode("tb", int(version), programint) // hrp (string), version (int), program ([]int)
                        } else {
                            address, _ = bech32.SegwitAddrEncode("bc", int(version), programint) // hrp (string), version (int), program ([]int)
                        }
                    }

                    scriptType = "p2wpkh"
                    //scriptTypeCount["p2wpkh"] += 1
                }

                // P2WSH
                if nsize == 40 && script[0] == 0 && script[1] == 32 { // P2WSH (script type is 40, which means length of script is 34 bytes)
                    // 956,1df27448422019c12c38d21c81df5c98c32c19cf7a312e612f78bebf4df20000,1,561890,800000,0,40,00200e7a15ba23949d9c274a1d9f6c9597fa9754fc5b5d7d45fc4369eeb4935c9bfe
                    version := script[0]
                    program := script[2:]

                    var programint []int
                    for _, v := range program {
                        programint = append(programint, int(v)) // cast every value to an int
                    }

                    if fieldsSelected["address"] { // only work out addresses if they're wanted
                        if testnet == true {
                            address, _ = bech32.SegwitAddrEncode("tb", int(version), programint) // testnet bech32 addresses start with tb
                        } else {
                            address, _ = bech32.SegwitAddrEncode("bc", int(version), programint) // mainnet bech32 addresses start with bc
                        }
                    }

                    scriptType = "p2wsh"
                    //scriptTypeCount["p2wsh"] += 1
                }

                // Non-Standard (if the script type hasn't been identified and set then it remains as an unknown "non-standard" script)
                if scriptType == "non-standard" {
                    //scriptTypeCount["non-standard"] += 1
                }

                // add address and script type to results map
                output["address"] = address
                output["type"] = scriptType

            }

        }
        csvchan <- output
    }
}



func logtofile()  {
    // Open file to write results to.
    f, err := os.Create(file) // os.OpenFile("filename.txt", os.O_APPEND, 0666)
    if err != nil {
        panic(err)
    }
    defer f.Close()
    fmt.Printf("Processing %s and writing results to %s\n", chainstate, file)

    // Create file buffer to speed up writing to the file.
    writer := bufio.NewWriter(f)
    defer writer.Flush() // Flush the bufio buffer to the file before this script ends

    //-----------------------------------------------------------------
    total := 1
    for output:= range csvchan {

        csvline := ""
        for _, v := range strings.Split(fields, ",") {
            if v == "count" {
                csvline += fmt.Sprintf("%d", total)
                csvline += ","
            } else {
                csvline += output[v]
                csvline += ","
            }

            if v == "type" {
                scriptTypeCount[output[v]] += 1
            }

        }
        csvline = csvline[:len(csvline)-1]
        if verbose {
            fmt.Println(csvline)
        }

        fmt.Fprintln(writer, csvline)
        total += 1
    }

}


func generate(wg *sync.WaitGroup){
    opts := &opt.Options{
        Compression: opt.NoCompression,
    }

    db, err := leveldb.OpenFile(chainstate, opts) // You have got to dereference the pointer to get the actual value
    if err != nil {
        fmt.Println("Couldn't open LevelDB.")
        fmt.Println(err)
        return
    }
    defer db.Close()

    // Stats - keep track of interesting stats as we read through leveldb.

    // Declare obfuscateKey (a byte slice)
    //var obfuscateKey []byte // obfuscateKey := make([]byte, 0)

    // Iterate over LevelDB keys
    iter := db.NewIterator(nil, nil)
    // NOTE: iter.Release() comes after the iteration (not deferred here)
    // err := iter.Error()
    // fmt.Println(err)
    var obfuscateKey []byte
    for iter.Next() {
        key := iter.Key()
        value := iter.Value()

        // first byte in key indicates the type of key we've got for leveldb
        prefix := key[0]

        if (prefix == 14) { // 14 = obfuscateKey
            obfuscateKey = value
        }
        if (prefix == 67) {
            DBdata2 := make(map[string][]byte)
            DBdata2["key"] = key
            DBdata2["value"] = value
            DBdata2["obfuscateKey"] = obfuscateKey
            //var DBdata2 = map[string][]byte{"key":key, "value": value, "obfuscateKey": obfuscateKey}
            //utx := &DBdata{key, value, obfuscateKey}
            dbchan <- DBdata2

            //fmt.Println(hex.EncodeToString(key), hex.EncodeToString(value))
        }

    }
    close(dbchan)
    iter.Release() // Do not defer this, want to release iterator before closing database

    wg.Done()
}


type DBdata struct {
    key []byte
    value []byte
    obfuscateKey []byte

}


var fieldsAllowed = []string{"count", "txid", "vout", "height", "coinbase", "amount", "nsize", "script", "type", "address"}

// Create a map of selected fields
var fieldsSelected = map[string]bool{"count":false, "txid":false, "vout":false, "height":false, "coinbase":false, "amount":false, "nsize":false, "script":false, "type":false, "address":false}

//var totalAmount int64 = 0 // total amount of satoshis
var scriptTypeCount = map[string]int{"p2pk":0, "p2pkh":0, "p2sh":0, "p2ms":0, "p2wpkh":0, "p2wsh":0, "non-standard": 0} // count each script type

var testnet = false
var verbose = false
var p2pkaddresses = false
var fields = ""
var file = ""
var chainstate = ""

//var dbchan = make(chan *DBdata, 100)
var dbchan = make(chan map[string][]byte, 3)
var csvchan = make(chan map[string]string, 100)

var dbchan2 = make(chan string, 5)


func main() {

    // Catch signals that interrupt the script so that we can close the database safely (hopefully not corrupting it)
    c := make(chan os.Signal, 1)
    signal.Notify(c, os.Interrupt, syscall.SIGTERM)
    go func() { // goroutine
        <-c // receive from channel
        fmt.Println("Interrupt signal caught. Shutting down gracefully.")
        // iter.Release() // release database iterator
        //db.Close()     // close databse
        //writer.Flush() // flush bufio to the file
        //f.Close()      // close file
        os.Exit(0)     // exit
    }()


    runtime.GOMAXPROCS(runtime.NumCPU())
    wg := sync.WaitGroup{}

    // Set default chainstate LevelDB and output file
    //defaultfolder := fmt.Sprintf("%s/.bitcoin/chainstate/", os.Getenv("HOME")) // %s = string
    defaultfolder := ".\\chainstate"
    defaultfile := ".\\utxodump2.csv"

    // Command Line Options (Flags)
    chainstate0 := flag.String("db", defaultfolder, "Location of bitcoin chainstate db.") // chainstate folder
    file0 := flag.String("o", defaultfile, "Name of file to dump utxo list to.") // output file
    fields0 := flag.String("f", "count,txid,address", "Fields to include in output. [count,txid,vout,height,amount,coinbase,nsize,script,type,address]")
    testnetflag := flag.Bool("testnet", false, "Is the chainstate leveldb for testnet?") // true/false
    verbose0 := flag.Bool("v", false, "Print utxos as we process them (will be about 3 times slower with this though).")
    p2pkaddresses0 := flag.Bool("p2pkaddresses", false, "Convert public keys in P2PK locking scripts to addresses also.") // true/false
    flag.Parse() // execute command line parsing for all declared flags

    p2pkaddresses = *p2pkaddresses0
    fields = *fields0
    file = *file0
    chainstate = *chainstate0
    verbose = *verbose0


    // Mainnet or Testnet (for encoding addresses correctly)
    if *testnetflag == true { // check testnet flag
        testnet = true
    } else { // only check the chainstate path if testnet flag has not been explicitly set to true
        if strings.Contains(chainstate, "testnet") { // check the chainstate path
            testnet = true
        }
    }

    // Check that all the given fields are included in the fieldsAllowed array
    for _, v := range strings.Split(fields, ",") {
        exists := false
        for _, w := range fieldsAllowed {
            if v == w { // check each field against every element in the fieldsAllowed array
                exists = true
            }
        }
        if exists == false {
            fmt.Printf("'%s' is not a field you can use for the output.\n", v)
            fieldsList := ""
            for _, v := range fieldsAllowed {
                fieldsList += v
                fieldsList += ","
            }
            fieldsList = fieldsList[:len(fieldsList)-1] // remove trailing comma
            fmt.Printf("Choose from the following: %s\n", fieldsList)
            return
        }
        // Set field in fieldsSelected map - helps to determine what and what not to calculate later on (to speed processing up)
        if exists == true {
            fieldsSelected[v] = true
        }
    }


    // Check chainstate LevelDB folder exists
    if _, err := os.Stat(chainstate); os.IsNotExist(err) {
        fmt.Println("Couldn't find", chainstate)
        return
    }

    // Select bitcoin chainstate leveldb folder
    // open leveldb without compression to avoid corrupting the database for bitcoin

    // https://bitcoin.stackexchange.com/questions/52257/chainstate-leveldb-corruption-after-reading-from-the-database
    // https://github.com/syndtr/goleveldb/issues/61
    // https://godoc.org/github.com/syndtr/goleveldb/leveldb/opt

    wg.Add(1)
    go generate(&wg)

    go logtofile()

    pool, _ := ants.NewPoolWithFunc(20, func(i interface{}) {
        parse(i)
        wg.Done()
    }, ants.WithPreAlloc(true))

    defer pool.Release()

    // something is wrong here:  utx from dbchan are repeated ???
    for utx := range dbchan {
        wg.Add(1)
        _ = pool.Invoke(utx)
    }

    wg.Wait()
    close(csvchan)

    // ----------------------------------------------------------------------------------------------------
    // ----------------------------------------------------------------------------------------------------


    fmt.Println()

    // Can only show script type stats if we have requested to get the script type for each entry with the -f fields flag
    if fieldsSelected["type"] {
        fmt.Println("Script Types:")
        for k, v := range scriptTypeCount {
            fmt.Printf(" %-12s %d\n", k, v) // %-12s = left-justify padding
        }
    }

}

package main
import "bytes"
import "io"
import "strings"
import "testing"

func TestGuess( tester * testing.T ) {
    var err error
    var hostnm string
    
    // HTTP
    hostnm , err = Guess( strings.NewReader( "GET / HTTP/1.1\r\nHost: konaa.ca:80\r\n\r\n" ) )
    if err != nil { tester.Fatalf( "%v\r\n" , err ) }
    if hostnm != "konaa.ca" {
        tester.Fatalf( "mismatch %v\r\n" , hostnm ) }
    hostnm , err = Guess( strings.NewReader( "GET / HTTP/1.1\r\n\r\n" ) )
    if err != nil { tester.Fatalf( "%v\r\n" , err ) }
    if hostnm != "" {
        tester.Fatalf( "mismatch %v\r\n" , hostnm ) }
    
    // TLS
    hostnm , err = Guess( bytes.NewReader( tlsClientHello ) )
    if err != nil { tester.Fatalf( "%v\r\n" , err ) }
    if hostnm != "konaa.ca" {
        tester.Fatalf( "mismatch %v\r\n" , hostnm ) }
        
    // Guess should return as soon as possible
    _ , err = Guess( io.MultiReader( bytes.NewReader( make( [ ]byte , 9999 , 9999 ) ) , & testRead{
        T : tester ,
    } ) )
    if err != nil { tester.Fatalf( "%v\r\n" , err ) }
    
}

type testRead struct{
    * testing.T
}
func ( self * testRead )Read( _ [ ]byte )( int , error ) {
    self.Fatalf( "over-read!" )
    return 0 , io.EOF
}

var tlsClientHello [ ]byte = [ ]byte{
    0x16 , 0x03 , 0x01 , 0x02 , 0x00 , 0x01 , 0x00 , 0x01 , 0xfc , 0x03 , 0x03 , 0x6a , 0x59 , 0xf8 , 0x88 , 0x71 , 
    0xbf , 0xba , 0xe7 , 0x75 , 0xf7 , 0x5f , 0xbc , 0xab , 0x1b , 0x90 , 0x17 , 0x29 , 0x77 , 0x74 , 0xfc , 0xd1 , 
    0xe5 , 0x6b , 0xb1 , 0x41 , 0x9b , 0x4c , 0x82 , 0x57 , 0xf1 , 0x6a , 0x59 , 0x20 , 0x72 , 0x07 , 0xe1 , 0x0c , 
    0x50 , 0xe6 , 0x7d , 0x91 , 0xfc , 0x77 , 0x57 , 0xe2 , 0x64 , 0x84 , 0x9f , 0x90 , 0x01 , 0x85 , 0x08 , 0x86 , 
    0xea , 0xcd , 0xaa , 0xe1 , 0x4f , 0xf6 , 0x65 , 0x98 , 0x0c , 0xfb , 0xe2 , 0x97 , 0x00 , 0x9c , 0x13 , 0x02 , 
    0x13 , 0x03 , 0x13 , 0x01 , 0xc0 , 0x2c , 0xc0 , 0x30 , 0x00 , 0xa3 , 0x00 , 0x9f , 0xcc , 0xa9 , 0xcc , 0xa8 , 
    0xcc , 0xaa , 0xc0 , 0xaf , 0xc0 , 0xad , 0xc0 , 0xa3 , 0xc0 , 0x9f , 0xc0 , 0x5d , 0xc0 , 0x61 , 0xc0 , 0x57 , 
    0xc0 , 0x53 , 0xc0 , 0x24 , 0xc0 , 0x28 , 0x00 , 0x6b , 0x00 , 0x6a , 0xc0 , 0x73 , 0xc0 , 0x77 , 0x00 , 0xc4 , 
    0x00 , 0xc3 , 0xc0 , 0x0a , 0xc0 , 0x14 , 0x00 , 0x39 , 0x00 , 0x38 , 0x00 , 0x88 , 0x00 , 0x87 , 0x00 , 0x9d , 
    0xc0 , 0xa1 , 0xc0 , 0x9d , 0xc0 , 0x51 , 0x00 , 0x3d , 0x00 , 0xc0 , 0x00 , 0x35 , 0x00 , 0x84 , 0xc0 , 0x2b , 
    0xc0 , 0x2f , 0x00 , 0xa2 , 0x00 , 0x9e , 0xc0 , 0xae , 0xc0 , 0xac , 0xc0 , 0xa2 , 0xc0 , 0x9e , 0xc0 , 0x5c , 
    0xc0 , 0x60 , 0xc0 , 0x56 , 0xc0 , 0x52 , 0xc0 , 0x23 , 0xc0 , 0x27 , 0x00 , 0x67 , 0x00 , 0x40 , 0xc0 , 0x72 , 
    0xc0 , 0x76 , 0x00 , 0xbe , 0x00 , 0xbd , 0xc0 , 0x09 , 0xc0 , 0x13 , 0x00 , 0x33 , 0x00 , 0x32 , 0x00 , 0x9a , 
    0x00 , 0x99 , 0x00 , 0x45 , 0x00 , 0x44 , 0x00 , 0x9c , 0xc0 , 0xa0 , 0xc0 , 0x9c , 0xc0 , 0x50 , 0x00 , 0x3c , 
    0x00 , 0xba , 0x00 , 0x2f , 0x00 , 0x96 , 0x00 , 0x41 , 0x00 , 0xff , 0x01 , 0x00 , 0x01 , 0x17 , 0x00 , 0x00 , 
    0x00 , 0x0d , 0x00 , 0x0b , 0x00 , 0x00 , 0x08 , 0x6b , 0x6f , 0x6e , 0x61 , 0x61 , 0x2e , 0x63 , 0x61 , 0x00 , 
    0x0b , 0x00 , 0x04 , 0x03 , 0x00 , 0x01 , 0x02 , 0x00 , 0x0a , 0x00 , 0x16 , 0x00 , 0x14 , 0x00 , 0x1d , 0x00 , 
    0x17 , 0x00 , 0x1e , 0x00 , 0x19 , 0x00 , 0x18 , 0x01 , 0x00 , 0x01 , 0x01 , 0x01 , 0x02 , 0x01 , 0x03 , 0x01 , 
    0x04 , 0x00 , 0x23 , 0x00 , 0x00 , 0x00 , 0x16 , 0x00 , 0x00 , 0x00 , 0x17 , 0x00 , 0x00 , 0x00 , 0x0d , 0x00 , 
    0x2a , 0x00 , 0x28 , 0x04 , 0x03 , 0x05 , 0x03 , 0x06 , 0x03 , 0x08 , 0x07 , 0x08 , 0x08 , 0x08 , 0x09 , 0x08 , 
    0x0a , 0x08 , 0x0b , 0x08 , 0x04 , 0x08 , 0x05 , 0x08 , 0x06 , 0x04 , 0x01 , 0x05 , 0x01 , 0x06 , 0x01 , 0x03 , 
    0x03 , 0x03 , 0x01 , 0x03 , 0x02 , 0x04 , 0x02 , 0x05 , 0x02 , 0x06 , 0x02 , 0x00 , 0x2b , 0x00 , 0x09 , 0x08 , 
    0x03 , 0x04 , 0x03 , 0x03 , 0x03 , 0x02 , 0x03 , 0x01 , 0x00 , 0x2d , 0x00 , 0x02 , 0x01 , 0x01 , 0x00 , 0x33 , 
    0x00 , 0x26 , 0x00 , 0x24 , 0x00 , 0x1d , 0x00 , 0x20 , 0x23 , 0xc7 , 0x27 , 0x9a , 0x96 , 0x50 , 0x86 , 0x68 , 
    0xc7 , 0x16 , 0xa2 , 0xad , 0x52 , 0x24 , 0xde , 0xae , 0xf1 , 0x47 , 0x6f , 0x17 , 0xc8 , 0xb3 , 0x8b , 0x9b , 
    0x97 , 0x61 , 0x73 , 0x60 , 0x39 , 0x4a , 0x2d , 0x62 , 0x00 , 0x15 , 0x00 , 0x69 , 0x00 , 0x00 , 0x00 , 0x00 , 
    0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 
    0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 
    0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 
    0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 
    0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 
    0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 ,
}

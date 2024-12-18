package main
import "bufio"
import "bytes"
import "crypto/tls"
import "io"
import "net"
import "net/http"
import "strings"
import "time"

// Guess, with buffer
func GuessB( reader io.Reader , buffer [ ]byte )( string , int , error ) {  // There's probably a more efficient way
    var err error
    var hostnm string
    buffer = buffer[ 0 : 0 ]
    var guessr [ ]func( io.Reader )( string , error ) = [ ]func( io.Reader )( string , error ){
        GuessHTTP ,
        GuessTLS ,
    }
    for {
        length := 0
        length , err = reader.Read( buffer[ len( buffer ) : cap( buffer ) ] )
        if length == 0 { return "" , len( buffer ) , err }
        buffer = buffer[ 0 : len( buffer ) + length ]
        for key , value := range guessr {
            hostnm , err = value( bytes.NewReader( buffer ) )
            if err == nil {
                return hostnm , len( buffer ) , nil }
            if err != io.ErrUnexpectedEOF {
                if len( guessr ) == 1 { return "" , len( buffer ) , nil }
                guessr[ key ] = guessr[ len( guessr ) - 1 ]
                guessr = guessr[ 0 : len( guessr ) - 1 ]
            }
        }
    }
}

// Tries to parse virtual host in all known protocols
func Guess( reader io.Reader )( string , error ) {
    var err error
    var hostnm string
    hostnm , _ , err = GuessB( reader , make( [ ]byte , 0 , 65535 ) )
    return hostnm , err
}

// GuessHTTP tries to parse HTTP virtual host
func GuessHTTP( reader io.Reader )( string , error ) {
    reques , err := http.ReadRequest( bufio.NewReader( reader ) )
    if err != nil { return "" , err }
    return strings.TrimRight( reques.Host , ":0123456789" ) , nil
}

// GuessTLS tries to parse TLS virtual host
func GuessTLS( reader io.Reader )( string , error ) {
    var tlssni string
    _ , err := ( tls.Server( fakeConn{
        Reader : io.MultiReader( reader , bytes.NewReader( make( [ ]byte , 100 , 100 ) ) ) ,
        Writer : io.Discard ,
        Closer : fakeClose ,
    } , & tls.Config{
        GetCertificate : func( hello * tls.ClientHelloInfo )( * tls.Certificate , error ){
            tlssni = " " + hello.ServerName
            return nil , nil
        } ,
    } ) ).Write( [ ]byte{ } )
    if len( tlssni ) > 0 {
        return tlssni[ 1 : len( tlssni ) ] , nil }
    return "" , err
}

// Fake net.Conn
type fakeConn struct{
    io.Reader
    io.Writer
    io.Closer
}
func ( self fakeConn )LocalAddr( )net.Addr {
    return fakeAddr{ }
}
func ( self fakeConn )RemoteAddr( )net.Addr {
    return fakeAddr{ }
}
func ( self fakeConn )SetDeadline( tlimit time.Time )error {
    return nil
}
func ( self fakeConn )SetReadDeadline( tlimit time.Time )error {
    return nil
}
func ( self fakeConn )SetWriteDeadline( tlimit time.Time )error {
    return nil
}

// Fake net.Addr
type fakeAddr struct{ }
func ( self fakeAddr )Network( )string {
    return "tcp"
}
func ( self fakeAddr )String( )string {
    return "localhost:80"
}

// Fake closer
type fakeCloseType struct{ }
func ( self fakeCloseType )Close( )error {
    return nil
}
var fakeClose fakeCloseType


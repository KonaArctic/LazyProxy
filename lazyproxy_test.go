package main
import "context"
import "io"
import "net"
import "net/http"
import "net/netip"
import "net/url"
import "testing"
import "strings"

var initial func( )error = func( )error {
    var err error
    var lzypxy * LazyProxy = & LazyProxy{
        MyAddr : netip.MustParseAddr( "127.5.39.228" ) ,
        Dialer : & testDialer{ } ,
    }
    err = lzypxy.Listen( )
    if err != nil { return err }
    go lzypxy.ServeDNS( )
    return nil
}

func TestLazyProxy( tester * testing.T ) {
    var err error
    err = initial( )
    if err != nil { tester.Fatalf( "%v\r\n" , err ) }
    initial = func( )error{ return nil }
    var respon * http.Response
    for _ , value := range [ ]string{ "example.com" , "example.org" , "example.com" } {
        respon , err = ( & http.Transport{
            Dial : ( & net.Dialer{
                Resolver : & net.Resolver{
                    Dial : func( ctx context.Context , network string , address string )( net.Conn , error ){
                        return net.Dial( "udp" , "127.5.39.228:53" )
                    } ,
                } ,
            } ).Dial ,
        } ).RoundTrip( & http.Request{
            Method : http.MethodGet ,
            URL : & url.URL{
                Scheme : "http" ,
                Host : value ,
            } ,
            Header : map[ string ][ ]string{ } ,
        } )
        if err != nil {
            tester.Fatalf( "%v\r\n" , err ) }
        if len( respon.Status ) < len( value ) + 4 {
            tester.Fatalf( "%v\r\n" , respon.Status ) }
        if respon.Status[ 4 : len( value ) + 4 ] != value {
            tester.Fatalf( "%v\r\n" , respon.Status ) }
    }
}

// Lazy Proxy is using too much RAM :(
func BenchmarkLazyProxy( bench * testing.B ) {
    var err error
    err = initial( )
    if err != nil { bench.Fatalf( "%v\r\n" , err ) }
    initial = func( )error{ return nil }
    _ , err = ( & net.Resolver{
        Dial : func( ctx context.Context , network string , address string )( net.Conn , error ){
            return net.Dial( "udp" , "127.5.39.228:53" )
        } ,
    } ).LookupNetIP( context.Background( ) , "ip" , "example.com" )  
    if err != nil { bench.Fatalf( "%v\r\n" , err ) }
    bench.ResetTimer( )
    var stream io.ReadWriteCloser
    for range bench.N {
        stream , err = net.Dial( "tcp" , "127.5.39.228:80" )
        if err != nil { bench.Fatalf( "%v\r\n" , err ) }
        _ , _ = stream.Write( [ ]byte( "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" ) )
        _ , _ = io.Discard.( io.ReaderFrom ).ReadFrom( stream )
    }
}

type testDialer struct{ }
func ( self * testDialer ) Dial( network string , address string )( net.Conn , error ) {
    return & fakeConn{
        Reader : strings.NewReader( "HTTP/1.1 200 " + address + "\r\n\r\n" ) ,
        Writer : io.Discard ,
        Closer : fakeClose , 
    } , nil
}


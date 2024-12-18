package main
import "flag"
import "errors"
import "golang.org/x/net/proxy"
import "io"
import "net"
import "net/netip"
import "net/url"
import "os"
import "time"
import "strings"

var setuid func( int )error = func( _ int )error{
    return errors.New( "not supported" )
}

func main( ) {
    var err error
    if len( os.Args ) < 3 {
        os.Exit( 2 ) }
    var lzypxy LazyProxy = LazyProxy{
        TLimit : time.Millisecond * 10 ,    // Good for LAN
        Predef : map[ string ]netip.Addr{ } ,
    }
    lzypxy.MyAddr , err = netip.ParseAddr( os.Args[ 1 ] )
    if err != nil || ! lzypxy.MyAddr.Is4( ) {
        os.Exit( 2 ) }
    pxyurl , err := url.Parse( os.Args[ 2 ] )
    if err != nil {
        os.Exit( 2 ) }
    lzypxy.Dialer , err = proxy.FromURL( pxyurl , & net.Dialer{ } )
    if err != nil {
        os.Exit( 2 ) }
    var flags flag.FlagSet
    flags.SetOutput( io.Discard )
    flags.Func( "resolv" , "" , func( value string )error{
        if strings.Index( value , "=" ) < 0 {
            return errors.New( "invalid argument" ) }
        lzypxy.Predef[ value[ 0 : strings.LastIndex( value , "=" ) ] ] , err = netip.ParseAddr( value[ strings.LastIndex( value , "=" ) + 1 : len( value ) ] )
        if err != nil { return errors.New( "invalid argument" ) } 
        return nil
    } )
    var newuid int = -1
    flags.IntVar( & newuid , "setuid" , -1 , "" )
    err = flags.Parse( os.Args[ 3 : len( os.Args ) ] )
    if err != nil { os.Exit( 2 ) }
    err = lzypxy.Listen( )
    if err != nil { os.Exit( 3 ) }
    if newuid > 0 {
        err = setuid( newuid )
        if err != nil { os.Exit( 4 ) }
    }
    err = lzypxy.ServeDNS( )
    if err != nil { os.Exit( 1 ) }
    os.Exit( 0 )
}


package main
import "syscall"

func init( ){
    setuid = func( newuid int )error{
        return syscall.Setreuid( newuid , newuid )
    }
}

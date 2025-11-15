package service

import "time"

func timeAfterSeconds(n int) <-chan struct{} {
	ch := make(chan struct{}, 1)
	go func() { time.Sleep(time.Duration(n) * time.Second); ch <- struct{}{} }()
	return ch
}

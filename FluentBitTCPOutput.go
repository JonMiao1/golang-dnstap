/*
 * Copyright (c) 2019 by Farsight Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package dnstap

import (
	"log"
	"net"
	"time"

        "github.com/golang/protobuf/proto"
)

// A FluentBitOutput manages a socket connection and sends dnstap
// data in json format over that connection
type FluentBitOutput struct {
	outputChannel chan []byte
	address       net.Addr
	wait          chan bool
	dialer        *net.Dialer
	timeout       time.Duration
	retry         time.Duration
	flushTimeout  time.Duration
}

// NewFluentBitOutput creates a FluentBitOutput managing a
// connection to the given address.
func NewFluentBitOutput(address net.Addr) (*FluentBitOutput, error) {
	return &FluentBitOutput{
		outputChannel: make(chan []byte, outputChannelSize),
		address:       address,
		wait:          make(chan bool),
		retry:         10 * time.Second,
		flushTimeout:  5 * time.Second,
		dialer: &net.Dialer{
			Timeout: 30 * time.Second,
		},
	}, nil
}


// GetOutputChannel returns the channel on which the
// FluentBitOutput accepts data.
//
// GetOutputChannel satisifes the dnstap Output interface.
func (o *FluentBitOutput) GetOutputChannel() chan []byte {
	return o.outputChannel
}


// RunOutputLoop reads data from the output channel and sends it over
// a connections to the FluentBitOutput's address, establishing
// the connection as needed.
//
// RunOutputLoop satisifes the dnstap Output interface.
func (o *FluentBitOutput) RunOutputLoop() {
	var connected bool
	var err error
	dt := &Dnstap{}
	// Start with the connection flush timer in a stopped state.
	// It will be reset by the first Write call on a new connection.
	conn := &timedConn{
		timer:   time.NewTimer(0),
		timeout: o.flushTimeout,
	}
	conn.StopTimer()

	defer func() {
		if conn != nil {
			conn.Close()
		}
		close(o.wait)
	}()

	for {
		select {
		case frame, ok := <-o.outputChannel:
			if !ok {
				return
			}

			// the retry loop
			for ;; time.Sleep(o.retry) {
				if !connected {
					// connect the socket
					conn.Conn, err = o.dialer.Dial(o.address.Network(), o.address.String())
					if err != nil {
						log.Printf("Dial() failed: %v", err)
						continue // = retry
					}
					connected = true
				}

				// try writing
				if err := proto.Unmarshal(frame, dt); err != nil {
					log.Fatalf("dnstap.FlutnBitOutput: proto.Unmarshal() failed %s\n", err)
					break
				}
				buf, ok := JSONFormat(dt)
				if !ok {
					log.Fatalf("dnstap.FluentBitOutput: text format function failed\n")
					break
				}
				if _, err = conn.Write(buf); err != nil {
					log.Printf("Connection write: net.Conn.Write() failed: %v", err)
					connected = false
					conn.Close()
					continue // = retry
				}

				break // success!
			}

		case <-conn.timer.C:
			conn.SetIdle()
			if !connected {
				continue
			}
		}
	}
}

// Close shuts down the FluentBitOutput's output channel and returns
// after all pending data has been flushed and the connection has been closed.
//
// Close satisifes the dnstap Output interface
func (o *FluentBitOutput) Close() {
	close(o.outputChannel)
	<-o.wait
}

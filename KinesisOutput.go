/*
 * Copyright (c) 2014 by Farsight Security, Inc.
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
	"fmt"
	"log"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kinesis"
	"github.com/golang/protobuf/proto"
)

// KinesisOutput implements a dnstap Output rendering dnstap data as text and shipping it to kinesis.
type KinesisOutput struct {
	format        TextFormatFunc
	outputChannel chan []byte
	wait          chan bool
	client        *kinesis.Kinesis
	streamname    string
}

// NewKinesisOutput creates a KinesisOutput writing dnstap data to the given aws client
// in the text format given by the TextFormatFunc format.
func NewKinesisOutput(streamname string, region string, format TextFormatFunc) (o *KinesisOutput, err error) {
	if format == nil {
		err = fmt.Errorf("Provide a text format flag for the data")
		return nil, err
	}
	o = new(KinesisOutput)
	o.format = format
	o.outputChannel = make(chan []byte, outputChannelSize)
	o.wait = make(chan bool)
	o.streamname = streamname

	var s *session.Session
	if region != "" {
		awsConfig := aws.Config{
			Region: aws.String(region),
		}
		s, err = session.NewSession(&awsConfig)
	} else {
		s, err = session.NewSession()
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to start session with AWS")
		return nil, err
	}
	o.client = kinesis.New(s)

	return o, nil
}

// GetOutputChannel returns the channel on which the KinesisOutput accepts dnstap data.
//
// GetOutputChannel satisfies the dnstap Output interface.
func (o *KinesisOutput) GetOutputChannel() chan []byte {
	return o.outputChannel
}

// RunOutputLoop receives dnstap data sent on the output channel, formats it
// with the configured TextFormatFunc, and writes it to the kinesis stream specified by
// KinesisOutput
//
// RunOutputLoop satisfies the dnstap Output interface.
func (o *KinesisOutput) RunOutputLoop() {
	dt := &Dnstap{}
	for frame := range o.outputChannel {
		if err := proto.Unmarshal(frame, dt); err != nil {
			log.Fatalf("dnstap.TextOutput: proto.Unmarshal() failed: %s\n", err)
			break
		}
		buf, ok := o.format(dt)
		if !ok {
			log.Fatalf("dnstap.TextOutput: text format function failed\n")
			break
		}
		//Send buf to kinesis
		_, err := o.client.PutRecord(&kinesis.PutRecordInput{
			Data:         buf,
			StreamName:   aws.String(o.streamname),
			PartitionKey: aws.String("key1"),
		})
		if err != nil {
			panic(err)
		}
	}

	close(o.wait)
}

// Close closes the output channel and returns when all pending data has been
// written.
//
// Close satisfies the dnstap Output interface.
func (o *KinesisOutput) Close() {
	close(o.outputChannel)
	<-o.wait
}

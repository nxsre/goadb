package main

import (
	adb "github.com/zach-klippenstein/goadb"
	"log"
)

func main() {
	client, err := adb.NewWithConfig(adb.ServerConfig{
		PathToAdb: "/opt/sdk/platform-tools/adb",
		Port:      6666,
	})
	if err != nil {
		log.Fatalln(err)
	}

	err = client.StartServer()
	if err != nil {
		log.Fatalln(err)
	}

	log.Println("连接")
	err = client.Connect("100.70.86.55", 40032)
	if err != nil {
		log.Fatalln(err)
	}

	listDevices(client)

	log.Println("断开连接")
	err = client.DisConnect("100.70.86.55", 40032)
	if err != nil {
		log.Fatalln(err)
	}

	listDevices(client)
}

func listDevices(client *adb.Adb) {
	devices, err := client.ListDevices()
	if err != nil {
		log.Fatalln(err)
	}

	for _, device := range devices {
		log.Printf("%+v", device)
	}
}

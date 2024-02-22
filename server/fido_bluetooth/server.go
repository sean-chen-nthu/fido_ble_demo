package main

import (
	"fmt"
	"log"

	"fido_bluetooth/option"
	"fido_bluetooth/service"

	_ "github.com/mattn/go-sqlite3"
	"github.com/paypal/gatt"
)

func main() {
	d, err := gatt.NewDevice(option.DefaultServerOptions...)
	if err != nil {
		log.Fatalf("Failed to open device, err: %s", err)
	}

	// Register optional handlers.
	d.Handle(
		gatt.CentralConnected(func(c gatt.Central) { fmt.Println("Connect: ", c.ID()) }),
		gatt.CentralDisconnected(func(c gatt.Central) { fmt.Println("Disconnect: ", c.ID()) }),
	)

	// A mandatory handler for monitoring device state.
	onStateChanged := func(d gatt.Device, s gatt.State) {
		fmt.Printf("State: %s\n", s)
		switch s {
		case gatt.StatePoweredOn:
			// Setup GAP and GATT services for Linux implementation.
			// OS X doesn't export the access of these services.
			d.AddService(service.NewGapService("Gophers")) // no effect on OS X
			d.AddService(service.NewGattService())         // no effect on OS X

			// A simple count service for demo.
			s1 := service.NewWebauthnService()
			d.AddService(s1)

			// A fake battery service for demo.
			s2 := service.NewLedService()
			d.AddService(s2)

			// Advertise device name and service's UUIDs.
			d.AdvertiseNameAndServices("Gophers", []gatt.UUID{s1.UUID(), s2.UUID()})

		default:
		}
	}

	d.Init(onStateChanged)
	select {}
}

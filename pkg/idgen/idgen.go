package idgen

import (
	"log"
	"time"

	"github.com/sony/sonyflake"
)

var sf *sonyflake.Sonyflake

func Init() {
	var st sonyflake.Settings
	st.StartTime = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	sf = sonyflake.NewSonyflake(st)
	if sf == nil {
		log.Fatal("sonyflake not created")
	}
}

func NextID() uint64 {
	id, err := sf.NextID()
	if err != nil {
		log.Fatalf("failed to generate next id: %v", err)
	}
	return id
}

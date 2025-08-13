package database

func InitConnection() error {
	if err := InitRedisConnection(); err != nil {
		return err
	}

	err := InitPgConnection()

	return err
}

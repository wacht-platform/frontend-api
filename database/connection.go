package database

func InitConnection() error {
	if err := InitRedisConnection(); err != nil {
		return err
	}

	if err := InitCeleryApp(); err != nil {
		return err
	}

	err := InitPgConnection()

	return err
}

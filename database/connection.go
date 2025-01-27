package database

func InitConnection() error {
	err := InitRedisConnection()
	if err != nil {
		return err
	}

	err = InitPgConnection()

	return err
}

package database

func InitConnection() error {
	if err := InitRedisConnection(); err != nil {
		return err
	}

	if err := InitPgConnection(); err != nil {
		return err
	}

	_ = InitClickHouseConnection()

	return nil
}

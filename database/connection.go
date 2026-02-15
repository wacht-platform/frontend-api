package database

func InitConnection() error {
	if err := InitRedisConnection(); err != nil {
		return err
	}

	if err := InitPgConnection(); err != nil {
		return err
	}

	err := InitClickHouseConnection()

	return err
}

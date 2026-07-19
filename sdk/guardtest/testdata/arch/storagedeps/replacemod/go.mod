module example.com/replacemod

go 1.26

require github.com/spf13/cobra v1.8.0

replace github.com/spf13/cobra => github.com/redis/go-redis/v9 v9.5.1

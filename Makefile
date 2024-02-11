all: test
test:
	./vendor/bin/phpunit --bootstrap ./tests/bootstrap.php tests
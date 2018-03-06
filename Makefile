all : install

clean :
	@echo ">>> Cleaning and initializing digestauth project <<<"
	@go clean
	@gofmt -w .
	@go get github.com/stretchr/testify

test : clean
	@echo ">>> Running unit tests <<<"
	@go test

test-coverage : clean
	@echo ">>> Running unit tests and calculating code coverage <<<"
	@go test -cover

install : test
	@echo ">>> Building and installing digestauth <<<"
	@go install
	@echo ">>> digestauth installed successfully! <<<"
	@echo ""

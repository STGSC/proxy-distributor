.PHONY: tidy vet lint test race bench testcov clean

# 基础操作
tidy:
	go mod tidy

vet:
	go vet ./...

lint:
	golangci-lint run --timeout=5m

# 测试相关
test:
	go test ./... -run . -count=1

race:
	go test ./... -race -run . -count=1

testcov:
	go test ./... -coverprofile=cover.out -covermode=atomic
	go tool cover -func=cover.out

# 基准测试
bench:
	go test ./... -bench=. -benchmem -run ^$

# 完整验证
verify: tidy vet lint race testcov
	@echo "所有检查通过"

# 清理
clean:
	go clean -cache
	rm -f cover.out
	rm -rf _refactor/attic/tests/*

# 基线生成
baseline: tidy
	@mkdir -p _refactor/baseline
	go vet ./... > _refactor/baseline/vet.out 2>&1 || true
	golangci-lint run --timeout=5m > _refactor/baseline/lint.out 2>&1 || true
	go test ./... -run . -count=1 > _refactor/baseline/test.out 2>&1 || true
	go test ./... -race -run . -count=1 > _refactor/baseline/race.out 2>&1 || true
	go test ./... -coverprofile=_refactor/baseline/cover.out -covermode=atomic
	go tool cover -func=_refactor/baseline/cover.out > _refactor/baseline/cover.txt
	go test ./... -bench=. -benchmem -run ^$ > _refactor/baseline/bench.txt 2>&1 || true
	@echo "基线已生成到 _refactor/baseline/"
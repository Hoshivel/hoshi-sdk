package lifecycle_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/hoshivel/hoshi-sdk/go/kit/lifecycle"
)

func TestShortAbbreviatesAndMarksDirty(t *testing.T) {
	t.Parallel()

	full := "395b0e5a80063ed54eaed6bf4a615bec32bc6dfc"

	for _, tc := range []struct {
		name  string
		build lifecycle.Build
		want  string
	}{
		{"clean", lifecycle.Build{Revision: full}, "395b0e5a8006"},
		{"dirty", lifecycle.Build{Revision: full, Modified: true}, "395b0e5a8006+dirty"},
		{"short revision is not padded", lifecycle.Build{Revision: "abc123"}, "abc123"},
		// 沒有 VCS 資訊時要明講「不知道」，不要回空字串——空字串在結構化
		// 日誌裡讀起來是「這個欄位沒設定」，那和「我們不知道這是哪一顆」不同。
		{"unknown", lifecycle.Build{}, "unknown"},
		{"unknown wins over modified", lifecycle.Build{Modified: true}, "unknown"},
	} {
		if got := tc.build.Short(); got != tc.want {
			t.Errorf("%s: Short() = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestLogAttrsOmitsUnknownFields(t *testing.T) {
	t.Parallel()

	withTime := lifecycle.Build{Revision: "abc123", Time: "2026-08-09T12:27:43Z"}
	if got, want := withTime.LogAttrs(), []any{"build", "abc123", "built_at", "2026-08-09T12:27:43Z"}; !slices.Equal(got, want) {
		t.Errorf("LogAttrs() = %v, want %v", got, want)
	}

	// 建置時沒有 VCS 資訊的話，只留一個講得出話的 build=unknown，
	// 不要補一排空字串。
	if got, want := (lifecycle.Build{}).LogAttrs(), []any{"build", "unknown"}; !slices.Equal(got, want) {
		t.Errorf("empty LogAttrs() = %v, want %v", got, want)
	}
}

func TestLogAttrsPairsUpForAStructuredLogger(t *testing.T) {
	t.Parallel()

	// slog 之類的 API 收的是交替的 key/value，落單的一個會變成 "!BADKEY"。
	// 這裡釘住長度是偶數，因為那個錯誤只有在真的送進 logger 時才看得出來。
	for _, b := range []lifecycle.Build{
		{},
		{Revision: "abc123"},
		{Revision: "abc123", Time: "2026-08-09T12:27:43Z", Modified: true},
	} {
		if n := len(b.LogAttrs()); n%2 != 0 {
			t.Errorf("LogAttrs() 長度 %d 是奇數，結構化 logger 會產生 !BADKEY", n)
		}
	}
}

func TestBuildOfIsStableAndDoesNotPanic(t *testing.T) {
	t.Parallel()

	// 在 `go test` 底下通常沒有 vcs.* 設定，所以這裡不斷言內容——
	// 斷言的是它不會炸，而且重複呼叫給同一個答案（結果有快取）。
	first := lifecycle.BuildOf()
	if second := lifecycle.BuildOf(); first != second {
		t.Errorf("BuildOf() 兩次結果不同：%+v vs %+v", first, second)
	}
	if s := first.Short(); s == "" {
		t.Error("Short() 回了空字串，它必須至少說得出 unknown")
	}
	if first.Revision != "" && strings.Contains(first.Short(), " ") {
		t.Errorf("Short() = %q，不該含空白（它會進日誌欄位）", first.Short())
	}
}

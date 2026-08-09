package identity

import "testing"

func TestUserInfoValidateSubject(t *testing.T) {
	id := IDToken{Subject: "usr_1"}
	if err := (UserInfo{Subject: "usr_1"}).ValidateSubject(id); err != nil {
		t.Fatal(err)
	}
	if err := (UserInfo{Subject: "usr_2"}).ValidateSubject(id); err == nil {
		t.Fatal("mismatched subjects must be rejected")
	}
}

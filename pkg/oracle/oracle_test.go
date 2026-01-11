package oracle

import (
	"testing"
)

func TestNewOracle11(t *testing.T) {
	o := NewOracle11()
	if o == nil {
		t.Fatal("NewOracle11() returned nil")
	}
	if len(o.Key) != 16 {
		t.Errorf("Oracle11.Key length = %d, want 16", len(o.Key))
	}
	if len(o.IV) != 16 {
		t.Errorf("Oracle11.IV length = %d, want 16", len(o.IV))
	}
}

func TestOracle11Encrypt(t *testing.T) {
	o := NewOracle11()
	plaintext := []byte("0123456789012345")
	ciphertext, err := o.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}
	if len(ciphertext) == 0 {
		t.Error("Encrypt() returned empty ciphertext")
	}
	if len(ciphertext) <= len(plaintext) {
		t.Errorf("Encrypt() ciphertext length %d should be > plaintext length %d", len(ciphertext), len(plaintext))
	}
}

func TestOracle11IsCBC(t *testing.T) {
	o := NewOracle11()
	_ = o.IsCBC()
	_ = o.IsECB()
	if o.IsCBC() == o.IsECB() {
		t.Error("IsCBC() and IsECB() should have opposite values")
	}
}

func TestNewOracle12(t *testing.T) {
	suffix := []byte("secret_suffix")
	o := NewOracle12(suffix)
	if o == nil {
		t.Fatal("NewOracle12() returned nil")
	}
	if len(o.Key) != 16 {
		t.Errorf("Oracle12.Key length = %d, want 16", len(o.Key))
	}
	if string(o.GetSuffix()) != string(suffix) {
		t.Errorf("GetSuffix() = %v, want %v", o.GetSuffix(), suffix)
	}
}

func TestOracle12Encrypt(t *testing.T) {
	suffix := []byte("secret")
	o := NewOracle12(suffix)
	plaintext := []byte("hello")
	ciphertext, err := o.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}
	if len(ciphertext) == 0 {
		t.Error("Encrypt() returned empty ciphertext")
	}
	if len(ciphertext)%16 != 0 {
		t.Errorf("Encrypt() ciphertext length %d not aligned to 16", len(ciphertext))
	}
}

func TestNewOracle13(t *testing.T) {
	o := NewOracle13()
	if o == nil {
		t.Fatal("NewOracle13() returned nil")
	}
	if len(o.Key) != 16 {
		t.Errorf("Oracle13.Key length = %d, want 16", len(o.Key))
	}
}

func TestOracle13ProfileFor(t *testing.T) {
	o := NewOracle13()
	tests := []struct {
		name  string
		email string
		want  string
	}{
		{
			name:  "simple email",
			email: "test@example.com",
			want:  "email=test@example.com&uid=10&role=user",
		},
		{
			name:  "email with special chars stripped",
			email: "test&role=admin@example.com",
			want:  "email=testroleadmin@example.com&uid=10&role=user",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := o.ProfileFor(tt.email)
			if got != tt.want {
				t.Errorf("ProfileFor() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOracle13Encrypt(t *testing.T) {
	o := NewOracle13()
	data := []byte("email=test@example.com&uid=10&role=user")
	ciphertext, err := o.Encrypt(data)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}
	if len(ciphertext) == 0 {
		t.Error("Encrypt() returned empty ciphertext")
	}
	if len(ciphertext)%16 != 0 {
		t.Errorf("Encrypt() ciphertext length %d not aligned to 16", len(ciphertext))
	}
}

func TestNewOracle14(t *testing.T) {
	suffix := []byte("secret_suffix")
	o := NewOracle14(suffix)
	if o == nil {
		t.Fatal("NewOracle14() returned nil")
	}
	if len(o.Key) != 16 {
		t.Errorf("Oracle14.Key length = %d, want 16", len(o.Key))
	}
	if len(o.Prefix) < 5 || len(o.Prefix) > 50 {
		t.Errorf("Oracle14.Prefix length = %d, want between 5 and 50", len(o.Prefix))
	}
	if string(o.GetSuffix()) != string(suffix) {
		t.Errorf("GetSuffix() = %v, want %v", o.GetSuffix(), suffix)
	}
}

func TestOracle14Encrypt(t *testing.T) {
	suffix := []byte("secret")
	o := NewOracle14(suffix)
	plaintext := []byte("hello")
	ciphertext, err := o.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}
	if len(ciphertext) == 0 {
		t.Error("Encrypt() returned empty ciphertext")
	}
	if len(ciphertext)%16 != 0 {
		t.Errorf("Encrypt() ciphertext length %d not aligned to 16", len(ciphertext))
	}
}

func TestNewOracle17(t *testing.T) {
	o := NewOracle17()
	if o == nil {
		t.Fatal("NewOracle17() returned nil")
	}
	if len(o.Key) != 16 {
		t.Errorf("Oracle17.Key length = %d, want 16", len(o.Key))
	}
	if len(o.Tokens) != 10 {
		t.Errorf("Oracle17.Tokens length = %d, want 10", len(o.Tokens))
	}
}

func TestOracle17EncryptToken(t *testing.T) {
	o := NewOracle17()
	ciphertext, iv := o.EncryptToken(0)
	if ciphertext == nil || iv == nil {
		t.Fatal("EncryptToken() returned nil ciphertext or IV")
	}
	if len(iv) != 16 {
		t.Errorf("EncryptToken() IV length = %d, want 16", len(iv))
	}
	if len(ciphertext) == 0 {
		t.Error("EncryptToken() returned empty ciphertext")
	}
	if len(ciphertext)%16 != 0 {
		t.Errorf("EncryptToken() ciphertext length %d not aligned to 16", len(ciphertext))
	}
}

func TestOracle17EncryptTokenInvalidIndex(t *testing.T) {
	o := NewOracle17()
	ciphertext, iv := o.EncryptToken(-1)
	if ciphertext != nil || iv != nil {
		t.Error("EncryptToken() with invalid index should return nil")
	}
	ciphertext, iv = o.EncryptToken(100)
	if ciphertext != nil || iv != nil {
		t.Error("EncryptToken() with invalid index should return nil")
	}
}

func TestOracle17DecryptToken(t *testing.T) {
	o := NewOracle17()
	plaintext := o.DecryptToken(0)
	if len(plaintext) == 0 {
		t.Error("DecryptToken() returned nil or empty plaintext")
	}
}

func TestOracle17DecryptTokenInvalidIndex(t *testing.T) {
	o := NewOracle17()
	plaintext := o.DecryptToken(-1)
	if plaintext != nil {
		t.Error("DecryptToken() with invalid index should return nil")
	}
	plaintext = o.DecryptToken(100)
	if plaintext != nil {
		t.Error("DecryptToken() with invalid index should return nil")
	}
}

func TestOracle17CheckPadding(t *testing.T) {
	o := NewOracle17()
	ciphertext, iv := o.EncryptToken(0)

	if !o.CheckPadding(ciphertext, iv) {
		t.Error("CheckPadding() should return true with correct IV")
	}

	if len(ciphertext) > 0 {
		modifiedCiphertext := make([]byte, len(ciphertext))
		copy(modifiedCiphertext, ciphertext)
		modifiedCiphertext[len(modifiedCiphertext)-1] ^= 0xFF
		_ = o.CheckPadding(modifiedCiphertext, iv)
	}
}

func TestRandomBytesAndInt(t *testing.T) {
	b1 := randomBytes(16)
	b2 := randomBytes(16)
	if len(b1) != 16 || len(b2) != 16 {
		t.Error("randomBytes() length mismatch")
	}
	different := false
	for i := range b1 {
		if b1[i] != b2[i] {
			different = true
			break
		}
	}
	if !different {
		t.Error("randomBytes() should generate different values")
	}

	i1 := randomInt(1, 100)
	i2 := randomInt(1, 100)
	if i1 < 1 || i1 > 100 || i2 < 1 || i2 > 100 {
		t.Errorf("randomInt() returned value out of range: %d, %d", i1, i2)
	}

	i3 := randomInt(50, 50)
	if i3 != 50 {
		t.Errorf("randomInt(50, 50) should return 50, got %d", i3)
	}
}

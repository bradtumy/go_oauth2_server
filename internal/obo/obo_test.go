package obo

import (
	"context"
	"testing"
	"time"

	internaljwt "go_oauth2_server/internal/jwt"
)

const testSigningKeyPEM = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCk3F5CWCLo296k
DRBCPt2wuhc9wbAdotnCt6prj+Ue4vQGFXzqybvqEr+M7g8YFOOIGA0jdoWMg7to
ztgLyLqjrq9LWVWI4ZeMalweI8wAQcT49EDrC7d/QITMeie/bQiXDMZOshE6eKkv
N1qjax1tgxiQW2vJNIGuZz3g0ytCjK+2HXxovkkzOm59FEzQ87gYwGQR75AAqnmt
Fa8eFXPGpa7eMSa+yJeQFjX4nQ1e16wnhueibheoJggrSSM+fkO9u5AWg+Synrld
ETb4iMP9ftQW9knkiaABFSGkZ/paMuWhzxaRSym+Z1Cf5amUpqKx0Bi/Ut5lVRJV
RpJA+6qFAgMBAAECggEAP0QKMC+ehfoKgK46tRFnBfEEBkEUEutx4dWV4t0/shCq
UMNiQr/UC0nSlISu6jDp+EoykI9lRL0w6FGoey024qWgw6uutW7NN6eBXleia97R
djBV0V2Xt4/M5qNiKYXwK/dNCtou3l97nZECiYALtQEAJjXPMVGjCoi4KFUhXtH7
yQHfCkoyRyPnIU3aYwzqXdaejyp2uCmLzprpPcg0NoFLh8lASSWUybPws3nEk7Bq
qGfGL9eGSm28gNCMu8O8CDWApOPfAyNi6CWbDBY5xf1uow/q2xX5V5bTPZwC3HsO
HtIiu6+JWcdlYifLUorYwuCeWAt2B7Nn0tsbpH5KKQKBgQDmnjZAms9XsfJ2/t43
L0LQTvx1H9iQUD0sghs1oWDifuAk+KrvfrzX6Cbvqw4dF/CWIl0segSkDHVZwQjP
FVMekQ4fnXTG6OsQeyjrjB2NWhM2oizY7FxzobEu/rhE+DpmlsFLlg80b6ZI+suJ
avAVo82W1rSxedYLd8dEAZIqEwKBgQC3AWlMqLob5ZUZlINyjlZ7VY1+EEUmtXPg
mRD97aLQxO/NG3G8LtMSs/VwXkRy25YZVIN2ZJe5QLsiwSspQ3yJuPfb5bQjWw2E
0CZvW7ZgRJoBFR6jxb3aLAvUoqPqokL6wlVA5VjGP0t4xzCBFVATn3kUWzbWlz2k
aXfpImHsBwKBgQCf0kEy4JaU5cNs6BBEGkKpbjPTT7Cbwp/CeqA0uJQWI2te894y
f5iL4F0rd1Yen3qh8Uq1ChKxRdkFzJs4OEUUR96L1mkZeE1/bHrdUosgbK4oDJgb
9SHVGNdcBDbbxVNjyVJH+cSryDxrEzN/FlcwCAbwY/dxj0fhRq8X2CbddQKBgCXC
+cpiqnxlJB3yIil6K2gpoBeaHdq96Fo422O6LDVt3ZlyB0bwVoducL+uA+u7Wb6C
TNoaKaCFNdgXCePq1ADLFQHf5QrCmAiGtteVkg1NOoXsqLTcca9aFVrb8HzS3IVH
ojXQ3T+TAey7FUwdbLeP2XkU1Tz0WjjZtm95s8DzAoGBAKMKN05H4h2s74TC3EJB
ud70LksnQheSBameXDdKe0t9ocCqYlR3L4ECIE3/qPEeHR+esphI9s4WgivGVZEL
s8Db464pzs9t0Z/+RowMN8nMuwXoybwSJYCdm83GEevJoZ4av5gaJCvIEjGHNCul
odOEQaR0ILGMQJZmpfvekDyK
-----END PRIVATE KEY-----`

func TestResolveAgentIgnoresSubjectAssertionClientID(t *testing.T) {
	signer, err := internaljwt.NewSigner("issuer", "aud", []byte(testSigningKeyPEM), "", time.Minute, time.Minute, time.Minute)
	if err != nil {
		t.Fatalf("init signer: %v", err)
	}
	service := Service{Signer: signer, Issuer: "issuer", Audience: "aud"}

	token, _, err := signer.IssueSubjectAssertion(context.Background(), "human-subject", time.Minute)
	if err != nil {
		t.Fatalf("issue subject assertion: %v", err)
	}

	claim, err := service.ResolveAgent(context.Background(), token, "urn:ietf:params:oauth:token-type:jwt", "client-app")
	if err != nil {
		t.Fatalf("resolve agent: %v", err)
	}
	if claim.ClientID != "client-app" {
		t.Fatalf("expected client-app client id, got %q", claim.ClientID)
	}
	if claim.Actor != "human-subject" {
		t.Fatalf("expected actor to fallback to subject, got %q", claim.Actor)
	}
}

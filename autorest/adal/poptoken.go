package adal

//EnablePoP - enable pop on subsequent Refresh()'ed acccess tokens
func (spt *ServicePrincipalToken) EnablePoP() {
	spt.enablePoP = true
}

func (tkn *Token) AcquirePoPToken(popClaims interface{}) (string, error) {

	/*
		alg := "RS256"
		sha := crypto.SHA256

		phead := fmt.Sprintf(`{"type":"JWT","alg":%q,"kid":"%s"}`, alg, tkn.poPKey.GetKID())
		var payload string
		if claimset != noPayload {
			cs, err := json.Marshal(claimset)
			if err != nil {
				return nil, err
			}
			payload = base64.RawURLEncoding.EncodeToString(cs)
		}
	*/

	return "", nil
}

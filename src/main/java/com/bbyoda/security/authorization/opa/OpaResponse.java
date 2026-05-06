package com.bbyoda.security.authorization.opa;

import lombok.Data;
import lombok.NoArgsConstructor;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@Data
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class OpaResponse {
    private Boolean result;

    public boolean isAllowed() {
        return Boolean.TRUE.equals(result);
    }
}

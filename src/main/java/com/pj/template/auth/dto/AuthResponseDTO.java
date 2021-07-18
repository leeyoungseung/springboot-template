package com.pj.template.auth.dto;

import lombok.*;

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthResponseDTO {

	private String accessToken;
	private String refreshToken;
	private String status;
	
}

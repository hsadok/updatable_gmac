.global ghash_register
ghash_register:
  movdqu (%rdi), %xmm0  # Load a
  movdqu (%rsi), %xmm8  # Load b
  movdqu (%rdx), %xmm5  # Load h^1 

  # Put a bit reversal pattern into xmm9
  mov $579005069656919567, %r8
  pinsrq $0, %r8, %xmm9
  mov $283686952306183, %r8
  pinsrq $1, %r8, %xmm9

  # Bit-reverse a and b
  pshufb %xmm9, %xmm0
  pshufb %xmm9, %xmm8

  # Compute Ghash_register
  vpxor %xmm0, %xmm8, %xmm0
  vpclmulqdq $0, %xmm5, %xmm0, %xmm1
  vpclmulqdq $16, %xmm5, %xmm0, %xmm2
  vpclmulqdq $1, %xmm5, %xmm0, %xmm3
  vpclmulqdq $17, %xmm5, %xmm0, %xmm5
  movdqu %xmm1, %xmm4
  vpxor %xmm3, %xmm2, %xmm6
  movdqu %xmm5, %xmm7
  pxor %xmm3, %xmm3
  mov $3254779904, %r11
  pinsrd $3, %r11d, %xmm3
  vpslldq $8, %xmm6, %xmm5
  vpxor %xmm5, %xmm4, %xmm4
  vpalignr $8, %xmm4, %xmm4, %xmm0
  vpclmulqdq $16, %xmm3, %xmm4, %xmm4
  vpsrldq $8, %xmm6, %xmm6
  vpxor %xmm6, %xmm7, %xmm7
  vpxor %xmm0, %xmm4, %xmm4
  vpalignr $8, %xmm4, %xmm4, %xmm8
  vpclmulqdq $16, %xmm3, %xmm4, %xmm4
  vpxor %xmm7, %xmm8, %xmm8
  vpxor %xmm4, %xmm8, %xmm8

  pshufb %xmm9, %xmm8   # Bit-reverse the result
  movdqu %xmm8, (%rdi)  # Store the result in a

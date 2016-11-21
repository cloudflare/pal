# PAL - Permissive Access Link

PAL is a tool for injecting secrets into Docker containers.
PAL consists of two components:

- `pald`: lives on the host, handles identity verification, secrets decryption
- `pal`: lives in the container, request secret decryption and setup container
  environment.

`pal` requires a `PAL_SECRETS_YAML` environment variable in your container.
`PAL_SECRETS_YAML` is broken into blocks named by environments.
The name of your desired environment must be provided to pal via the `-env` flag or via the `APP_ENV` environment variable.
The environments are further divided into `env` and `file` blocks, each of which is a YAML dictionary.
The `env` block maps environment variable names to their contents,
while the `file` block maps file paths to their contents.
`pal` writes files as the current container's user, but the file
permissions must be set by the chosen command if necessary.

Both blocks admit contents in one of these schemes, denoted by adding a prefix to the contents:

- ro: Red October encrypted data.
  The value placed under the key will be returned after Red October decryption.
- ro+base64: Red October encrypted, base64-encoded data.
  The value placed under this key will be returned after Red October decryption
  followed by base64 decoding. This is useful for binary data, as Red October
  only handles secrets encoded as strings.
- pgp: PGP encrypted data.
  The value placed under the key will be returned after `pald` decrypt it using
  one of its configured keyrings
- pgp+base64: PGP encrypted, base64-encoded data.
- No prefix: Data with no prefix are just returned as read from the file.
  This is useful for defining a development environment with well-known secrets.

An example of `PAL_SECRETS_YAML` is as follow:

```
PAL_SECRETS_YAML: |
  dev:
    env:
      SECRET: "This is not secret"
    file:
      /usr/local/secret.txt: "Neither is this"
  production:
    env:
      SECRET: |
        ro:eyJWZXJzaW9uIjotMSwiRGF0YSI6ImV5SldaWEp6YVc5dUlqb3hMQ0pXWVhWc2RFbGtJam8
        TnpNMU5EY3pPREVzSWt0bGVWTmxkQ0k2VzNzaVRtRnRaU0k2V3lKQmJHbGpaU0lzSWtKdllpSm
        RMQ0pMWlhraU9pSXdkMjVvVWtaVmVGTkVRUzlWUmpkWk4wVmxNMngzUFQwaWZWMHNJa3RsZVZO
        bGRGSlRRU0k2ZXlKQmJHbGpaU0k2ZXlKTFpYa2lPaUoyWkhSSVRuWnpiRGxQZVRSYWNWZDFVRE
        p0TlZoWlRYYzBPRTlRWjFwSlRIbHljR05rS3pjdk9EVnNObGR6Tm0wd2VYTnBkamxRVnpGMEsx
        VTFaR2hXZFVwU1ZETnRTR0poYTFBNGNVOUthamhCTjFSM2EycFZVRU4xYWtoelQwMVdSVFZRVm
        1ndk9WVXlSMXBEZVdseVRIVk1aSG92VTBSclVsUmpZVXRGTDBoM1RIZEplbGxyVTBaS1QzQlJa
        ME01WjFGbmVEZzJPR1JMZVdnM00wWTRjbXM0TjB0eWFDOW1UM3BDVkRWRVJXeDJabTFXTWtkRF
        UwbFJhVFJFUml0MFVqZGlVM2htVmtKa1R6VXphVFJLYVdWcWRUaE1OWHBuTW5oTFIxbGpjblp6
        YTNoRlExZHRRbXNyYlc1T2NtOU5aRFpCUXpNeVJrZ3ZTR2xHWVVkRlkzbGlSVmR0U2xkMFUyZF
        pXR3MwYmt4bE5YSkJaMUo0ZUZST04xVXdha3hPTURSSlNsWk1WV3RxWmxOWU1ESlhTMnBqZFVG
        MFVuZEZhVGt3TW10WVZsUkpXVVJ3WVRaV2RuTlBiRWxCWTNvelIwcEtTbWM5UFNKOUxDSkNiMk
        lpT25zaVMyVjVJam9pUm1WUllYSkxVV3RyUzJrM09GbFBNekpCTnk5MldsSnRkWFowYWtsTmJr
        OW1ablpvUVVGeVJqbDJUMWd2UjI1WE1GbDJNRGwxT0VSRVJWQnNjVUp5TlhkSlR6QnlNM0Z3ZW
        1SeU5DOVhhamxqYkN0aGNHMTFZVEZhUW5oRlZpOUNTVk00VFVGWFZEUjBWalpDWm1wUWEwZFdM
        MmxsZFVORmNrbEtTa1pzVmxwTE0zYzJRWFZQTkc5aVkwNUpjVlZ0YjNWclJVVkxVek01TVdKNW
        NERlFOVTB6YkVack9USTRjbWhwWTBZd1FucEJSVWhYZFhkS1kzbE9OM0p5VlhkVU5EUXJlVzFp
        YlVsdU9UY3lkRGxYSzI5dFlVTm9VVmhuZFUwdll6SkNZMnByVERCNGJIZHViVEJTY205cmVEVl
        NjSFpSS3paMU1TdEJhbmd5WjNoMmRGaFNha296YkRGV01GUmlUeXMyVWxJclRVOTVRa1Z0Unk5
        R1VEVllOMGx3VkZsWlZVUk9RMnczYzJKemVqWkhZa3hLTTNoaUsyTjZjV1JGTUhkNlZubEtXbF
        I2V0c1UFEwOHplWFJwY1hobVlVSnRjVkIzUFQwaWZYMHNJa2xXSWpvaVZsUXpaMm9yV1hoTlRH
        YzBiVzk1UTJkd05uUTVkejA5SWl3aVJHRjBZU0k2SW5aMWJWVkJSa1pvWlRSUFFuQjBNak5yTj
        JkaVFsRTlQU0lzSWxOcFoyNWhkSFZ5WlNJNkluSnlSM2RtU3lzclRXVnhSREZtVUM5aU1GQlVi
        M1JQY0ZrNVVUMGlmUT09IiwiU2lnbmF0dXJlIjoiS0FrS21PK0J1UzU5ai8vbWZjSDN1a3BVeD
        JjPSJ9
    file:
      /usr/local/secret.txt: |
        ro:eyJWZXJzaW9uIjotMSwiRGF0YSI6ImV5SldaWEp6YVc5dUlqb3hMQ0pXWVhWc2RFbGtJam9
        4TlRZek56WTFPREF3TENKTVlXSmxiSE1pT2xzaWNHRnNMV1Y0WVcxd2JHVWlYU3dpUzJWNVUyV
        jBJanBiZXlKT1lXMWxJanBiSW1wcmNtOXNiQ0lzSW1KbGJtSjFjbXRsY25RaVhTd2lTMlY1SWp
        vaVpIbGtLMm95U1VGdFZYa3JOeXR4TDI1RVkzaExRVDA5SW4xZExDSkxaWGxUWlhSU1UwRWlPb
        nNpWW1WdVluVnlhMlZ5ZENJNmV5SkxaWGtpT2lKbFp6RnZUME5xWWxoM1VHWkJOVnBCV21Gd2N
        sQTJka1pRUmxweGN6QmFRa0pzWVUxdk4ydHZiV1p2Y200M1pqZ3lkQ3MyZDNJNVNEVkdhbVExT
        ms5SlExWm5jVGRZVVVNeGRXSkViMkkyY1ZseE5rbEdaSHBsU0hWV0wzZEhla3BOVjNWdlZGUlB
        aVEJvTHpoWE1WTkZWRWh0VUZBMFdqaHZiR0pGSzFsTE9YaFZUMDFuYkdaWmFXOVRhRGR5WTBaS
        FlsWXZSa1ZCYVROcU0yMW1ZV0ZsVVRjd09IY3JZMmRyVFUxU2VIUmtTRFExU1VRNFJEVkpNR3c
        wUkdNNU5FWmhZalJXUkVoNlQzbzROeTlQTjNwRFRuRTRWemhEUkhCWE9XTmpURk5tTnpCS1dqZ
        EthRkJpWWl0U1VWaG5aWG80V0hBMU5VNUtXa3RpVW01R09FUTJRbGxYVUc5Sk5uTkdTVGhwVTB
        0T2FUTXdNbGRrTVU1a1IwUkllR3BLTVRKUWRtUjRTbTkyTUcxMlpXd3ZORk5ZVm5oYVEweHBNS
        GxYUTNGaWJpdHBSMUZXWTJwVVRrbHBRMDVVVFcxT2NFUmpiVFppWjNjOVBTSjlMQ0pxYTNKdmJ
        Hd2lPbnNpUzJWNUlqb2lVVkZTT1hjNFFubHlhbWMzUmpaNFZFczRZMXBuVVZvd2RVZE1TVmt3V
        EhsTmRpOVRhRXBIU1V0V2JXRXpRelZNTkVrNFFuTXlSMGw0Tld0TFoxZExjbmhTUnpWQlprMVV
        XVVp2V1RNMVprbGhRM2RaTmtreksxSklSelJ4TVdkMVptWkRObmRrWlRVd1V6SnNTaTg0Wm1Wa
        1prSlVibTlCVDFjekt6aE1VMmN2TWtnd2FtOTRkVkJrU201dVdUVk9XV0pSYWxKME4yaG9PVmh
        4VDIxSmVtMVFOak5zWlVocE9FNHZTMUpOUlhGc1lqQTlJbjE5TENKSlZpSTZJbXAzTm5CQ1prZ
        EthbnByTm1KVVVGWXZOMFE1UmtFOVBTSXNJa1JoZEdFaU9pSnBWa3BwY21kQ1QxUnlNR3BhYzF
        GWFdEUXliR3hCUFQwaUxDSlRhV2R1WVhSMWNtVWlPaUpqTm1GQlIwbGFRbXNyV2toVFpuUmFVb
        EpDZDFGUlkwWkJNMFU5SW4wPSIsIlNpZ25hdHVyZSI6IkJaWnFXcjZ1TGYzcjZocFVCbmxtU2l
        KcUtSbz0ifQ==
```

## Building and testing

- `make`: run the unit tests then build the binaries
- `make test`: run unit tests
- `make integration`: run the integration test stack including redoctober,
  pal and pald. It will try to generate RedOctober encrypted secrets and also
  PGP encrypted secrets then try to decrypt them with the pal client.

$policy=Get-Content -path "C:\GitHub\GuestAttestationCustomTenant\TVMpolicy.txt" -Raw
Set-AzAttestationPolicy -Name $attestationProvider -ResourceGroupName $attestationResourceGroup-Tee $teeType-Policy $policy-PolicyFormat $policyFormat


$policy = Get-Content -Path "C:\GitHub\GuestAttestationCustomTenant\CurrentMAA\Policy\BaseLinePolicy.txt" | Out-String
Set-AzAttestationPolicy -Name testtenant -ResourceGroupName sirlinrgattest -Tee AzureGuest -Policy $policy
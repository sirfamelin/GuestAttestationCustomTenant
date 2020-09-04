$vmResourceGroup = "sirlinw2"
$vmName = "vm1"
$vm = Get-AzVM -ResourceGroupName $vmResourceGroup -Name $vmName
Update-AzVM -ResourceGroupName $vmResourceGroup -VM $vm -AssignIdentity:$SystemAssigned

$vm = Get-AzVM -ResourceGroupName $vmResourceGroup -Name $vmName
$sp = Get-AzADServicePrincipal -ObjectId $vm.Identity.PrincipalId
$sp

Write-Host "Application Id:" $sp.ApplicationId.Guid 
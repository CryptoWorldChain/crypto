function checkAllBalances() { 
  var i =0; 
  console.log("hello")
  eth.accounts.forEach( function(e){
    console.log("  eth.accounts["+i+"]: " +  e + " \tbalance: " + web3.fromWei(eth.getBalance(e), "ether") + " ether"); 
    i++; 
  })
};




function signtest() { 
  var i =0; 
  personal.unlockAccount("0xb844679265b3ff140199f31d4d8219c2dbad05e6", "wdcwdcwdc");
  var sign=web3.eth.sign("0xb844679265b3ff140199f31d4d8219c2dbad05e6",web3.sha3("hello"))
  console.log("sign="+sign);
  var start=(new Date()).getTime();
	console.log("sign="+sign+",startat="+start);
  for(i =0;i<100000;i++)
  {
  	var addr=personal.ecRecover(web3.sha3("hello"),sign);
  }
  var end=(new Date()).getTime();
  console.log("addr="+addr+",endat="+end+",cost="+(end-start));
};
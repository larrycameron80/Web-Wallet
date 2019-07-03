$(document).ready(function(){
	$(".nav.navbar-nav a").click(function(){
		// console.log(123)
		$(".nav.navbar-nav li").removeClass("active")
		$(this).parent().addClass("active")
	   var section = $(".section."+$(this).attr("section"))
	   $("body > .section").hide()


	   $("body").attr("section",$(this).attr("section"))
	   section.show()

	})

	$("a[href='#send-spend']").click(function(){  
		$("a[href='#create-tx']").click()
	})

	$("a[href='#staking']").click(function(){  
		$("a[href='#delegate-tx']").click()
	})



	// txTemplate.json
	var txTemplate={"type":"auth/StdTx","value":{"msg":[{"type":"cosmos-sdk/MsgSend","value":{"from_address":"","to_address":"","amount":[{"denom":"","amount":""}]}}],"fee":{"amount":[],"gas":"200000"},"signatures":null,"memo":""}}




	// signatureTemplate.json
   var signatureTemplate ={"pub_key": {"type": "tendermint/PubKeySecp256k1","value":""},"signature": ""}


   var stakingTemplate ={"type": "auth/StdTx","value":{"msg":[{"type":"cosmos-sdk/MsgDelegate","value":{"delegator_address":"spend","validator_address":"spendvaloper","amount":{"denom":"stake","amount":"150000000"}}}],"fee": {"amount": [],"gas": "200000"},"signatures": null,"memo": ""}}

	var newTx =  {} 

	$("#generate-wallet").click(function(){
		var mnemonic = spendCrypto.generateMnemonic(); 
		var wallet = spendCrypto.getWalletFromSeed(mnemonic);
		$("#new-mnemonic").val(mnemonic);
		$("#new-private").val(wallet.keys.private.hex);
		$("#new-public").val(wallet.keys.public.bech32.string);
		$("#new-address").val(wallet.address.bech32.string);
		// this must be first
		$(".new-wallet.note").show()
	})

	$("#old-mnemonic").on("keyup change",function(){
		var mnemonic = $("#old-mnemonic").val().trim().replace(/\s{2,}/g, ' ');
		
		var wallet = spendCrypto.getWalletFromSeed(mnemonic);
		$("#private-from-mnemonic").val(wallet.keys.private.hex);
		$("#public-from-mnemonic").val(wallet.keys.public.bech32.string);
		$("#address-from-mnemonic").val(wallet.address.bech32.string);
	})

   $("#continue-tx").click(generateTx)
   $("#continue-tx").click(function(){
   	$("#tx").val($("#new-tx").val())
   	$(".section.send-spend a[href='#sign']").click()
   	$("#request-info").click()
   })


   $("#continue-stake").click(generateStakingTx)
   $("#continue-stake").click(function(){
   	$("#tx").val($("#stake-tx").val())
   	$(".section.send-spend a[href='#sign']").click()
   	$("#request-info").click()
   })


	// $(".section.generate-transaction input ,.section.generate-transaction select ").on("change keyup", generateTx)
	
	function generateTx(){
		var newTx = JSON.parse(JSON.stringify(txTemplate)) ;
		newTx.value.msg[0].value= {
	       "from_address": 	$("#from-address").val().trim().replace(/\s{1,}/g, ''),
	       "to_address": 	$("#to-address").val().trim().replace(/\s{1,}/g, ''),
	       "amount":[
	          {
	             "denom": 	$("#coin").val(),
	             "amount": 	$("#amount").val()
	          }
	       ]
	    }
	    if($("#indent").prop("checked")){
	    	$("#new-tx").val(JSON.stringify(newTx, null, 2))
	    	$("#new-tx").height("410px")
	    }else{
	    	$("#new-tx").val(JSON.stringify(newTx))
	    	$("#new-tx").height("95px")
	    }
	}

	function generateStakingTx(){
		var newTx = JSON.parse(JSON.stringify(stakingTemplate)) ;

		// console.log(1231231)
		newTx.value.msg[0].value= {
	       "delegator_address": 	$("#from-delegator").val().trim().replace(/\s{1,}/g, ''),
	       "validator_address": 	$("#to-validator").val().trim().replace(/\s{1,}/g, ''),
	       "amount":
	          {
	             "denom": 	$("#coin-stake").val(),
	             "amount": 	$("#amount-stake").val()
	          }
	       
	    }
		console.log(newTx)
	    if($("#indent").prop("checked")){
	    	$("#stake-tx").val(JSON.stringify(newTx, null, 2))
	    	$("#stake-tx").height("410px")
	    }else{
	    	$("#stake-tx").val(JSON.stringify(newTx))
	    	$("#stake-tx").height("95px")
	    }
	}

	// resizing, not part from process
	$("#tx , #mnemonic-for-sign").on("keyup change",function(){
	    $(this)[0].style.height = "5px";
	    $(this)[0].style.height = ($(this)[0].scrollHeight)+"px";

	    if($(this).parent().is(".half")){
	    	$(this).parent().next(".half").find("textarea")[0].style.height =  $(this)[0].style.height
	    }
	})

	$("#request-info").on("click",function(){
		var tx = JSON.parse($("#tx").val());
		var fromAddress = typeof(tx.value.msg[0].value.from_address) == "undefined" ? tx.value.msg[0].value.delegator_address :  tx.value.msg[0].value.from_address  ;
		fetchAccountInfo(fromAddress);
	})


	function fetchAccountInfo (accAddress){
	   // url can be configurable too, example localhost
		var url = "http://18.185.105.50:9071/auth/accounts/"

		$.ajax({
		  dataType: "json",
		  url: url+accAddress,
		  success: function(response){
		  		$("#account-number").val(response.account.value.account_number)
		  		$("#sequence").val(response.account.value.sequence)
		  		$("#sequence").change()
		  }
		});
	}


	// $("#mnemonic-for-sign").on("keyup change",function(){
	$("#make-signature").on("click",function(){
		var mnemonic = $("#mnemonic-for-sign").val().trim().replace(/\s{2,}/g, ' ');
		var wallet = spendCrypto.getWalletFromSeed(mnemonic);
		$("#private-for-sign").val(wallet.keys.private.hex)
		doSigning()
	})


	$("#broadcast-transaction").on("click",function(){
		var settings = {
			"async": true,
			"crossDomain": true,
			"url": "http://18.185.105.50:9071/txs",
			"method": "POST",
			"headers": {
				"Content-Type": "application/json",
			},
			"data": $("#signed-tx").val()
		}
		$.ajax(settings).done(function (response) {
		   $("#hash").val(response.txhash);
		   $("#view-tx").attr("href", "http://18.194.28.213:3000/transactions/"+response.txhash);
			$(".section.send-spend a[href='#broadcast']").click()
		})
	})		

	 // $("#tx").on("keyup change",doSigning)
	 // $(" #private-for-sign , #indent-signed , #account-number , #sequence").on("keyup change",doSigning)
	function doSigning(){
		var tx = JSON.parse($("#tx").val());

		tx = tx.value
		tx["account_number"] = $("#account-number").val()
		tx["sequence"] = $("#sequence").val()
		tx["chain_id"] = "spend";
		tx["msgs"] = tx["msg"];
		delete (tx.msg);
		tx = utils.abcSortJson(tx);
		var privHex =$("#private-for-sign").val().trim().replace(/\s{2,}/g, ' ');

		info  = spendCrypto.getAddressFromPrivateKey(privHex)
		// {publicKey, address} = spendCrypto.getAddressFromPrivateKey(privHex)

		// var fromAddress = tx["msgs"][0].value.from_address
		var fromAddress = typeof(tx.msgs[0].value.from_address) == "undefined" ? tx.msgs[0].value.delegator_address :  tx.msgs[0].value.from_address  ;

		if(fromAddress == info.address){
			var priv = spendCrypto.bufferFromHex(privHex)
			var signature = spendCrypto.signWithPrivateKey(tx ,priv ).signature.toString("base64") 
			var sigTamplate = JSON.parse(JSON.stringify(signatureTemplate))
			
			sigTamplate.signature=signature
			sigTamplate.pub_key.value = info.publicKey


			// return to starting position	
			tx =  {tx:JSON.parse($("#tx").val())};


			tx.tx.value.signatures=[sigTamplate]

			tx.tx = tx.tx.value
			tx.mode="block"

			tx["account_number"] = $("#account-number").val()
			tx["sequence"] = $("#sequence").val()

		   if($("#indent-signed").prop("checked")){
		    	$("#signed-tx").val(JSON.stringify(tx, null, 2))
		    	$("#signed-tx").height("595px")
		   }else{
		    	$("#signed-tx").val(JSON.stringify(tx))
		    	$("#signed-tx").height("95px")
		   }
		}else{
			$("#signed-tx").val("Please insert valid Mnemonic or Private Key")
		}

	}

	if(location.hash.substr(1)==""){
		window.location="#send-spend"
	}
	 $("a[section='"+location.hash.substr(1)+"']" ).click()
	 
	window.onhashchange = function(){
		 $("a[section='"+location.hash.substr(1)+"']" ).click()
	};


	 $("body").show()
})

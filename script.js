$(document).ready(function(){
	 test()

	function test(){
		var autoRefresh = { timeout:false , interval:false , index:1 , change:0 }
		function setAutoRefresh(){
			if(autoRefresh.timeout) clearTimeout(autoRefresh.timeout)
			if(autoRefresh.interval) clearInterval(autoRefresh.interval)

			$("body").css("opacity", 1)
			 autoRefresh.change = 0.9999999;


			autoRefresh.index = 1
			autoRefresh.interval =setInterval(function(){

				autoRefresh.change = autoRefresh.change * autoRefresh.change 
				autoRefresh.index++
				newOpp = $("body").css("opacity")* autoRefresh.change;
				$("body").css("opacity",newOpp )

			},1000)

			autoRefresh.timeout = setTimeout(function(){
				window.location = ""; 
			},25000)
		}
		$(document).ready(function(){

			$("input#from-address").val($("#address-from-mnemonic").val())
			$("input#from-address").change()

			$("input#to-address").val("")
			$("input#amount").val(500)
			$("select#coin").val("stake")

			$("textarea#old-mnemonic").change()
			$("input#from-address").change()
			$("#generate-wallet").click()
			
			$("#tx").val( $("#new-tx").val()) 
			$("#tx").change()
			$("#request-info").click()

			$("#mnemonic-for-sign").val($("#old-mnemonic").val())
			$("#mnemonic-for-sign").change();

		})
	}

	var txTemplate={
	   "type":"auth/StdTx",
	   "value":{
	      "msg":[
	         {
	            "type":"cosmos-sdk/MsgSend",
	            "value":{
	               "from_address":"",
	               "to_address":"",
	               "amount":[
	                  {
	                     "denom":"stake|spend",
	                     "amount":""
	                  }
	               ]
	            }
	         }
	      ],
	      "fee":{
	         "amount":[],
	         "gas":"200000"
	      },
	      "signatures":null,
	      "memo":""
	   }
	}
	var newTx = JSON.parse(JSON.stringify(txTemplate))


	$("#generate-wallet").click(function(){
		var mnemonic = spendCrypto.generateMnemonic() ; 
		var wallet = spendCrypto.getWalletFromSeed(mnemonic)
		$("#new-mnemonic").val(mnemonic)
		$("#new-private").val(wallet.keys.private.hex)
		$("#new-public").val(wallet.keys.public.bech32.string)
		$("#new-address").val(wallet.address.bech32.string)
		$(".new-wallet.note").show()
	})


	$("#old-mnemonic").on("keyup change",function(){
		var mnemonic = $("#old-mnemonic").val().trim().replace(/\s{2,}/g, ' ');
		
		var wallet = spendCrypto.getWalletFromSeed(mnemonic);

		$("#private-from-mnemonic").val(wallet.keys.private.hex);
		$("#public-from-mnemonic").val(wallet.keys.public.bech32.string);
		$("#address-from-mnemonic").val(wallet.address.bech32.string);
	})

	$(".section.generate-transaction input ,.section.generate-transaction select ").on("change keyup", function(){

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
	})

	$("#tx , #mnemonic-for-sign").on("keyup change",function(){
		    $(this)[0].style.height = "5px";
		    $(this)[0].style.height = (  $(this)[0].scrollHeight)+"px";


		    if($(this).parent().is(".half")){
		    	$(this).parent().next(".half").find("textarea")[0].style.height =  $(this)[0].style.height
		    }

	})

	$("#request-info").on("click",function(){
		var tx = JSON.parse($("#tx").val());
		var fromAddress = tx.value.msg[0].value.from_address
	   // this can be configurable too
		var url = "http://18.185.105.50:9071/auth/accounts/"
		$.ajax({
		  dataType: "json",
		  url: url+fromAddress,
		  success: function(response){
		  		$("#account-number").val(response.account.value.account_number)
		  		$("#sequence").val(response.account.value.sequence)
		  }
		});

	})


	 $("#mnemonic-for-sign").on("keyup change",function(){
		var mnemonic = $("#mnemonic-for-sign").val().trim().replace(/\s{2,}/g, ' ');
		var wallet = spendCrypto.getWalletFromSeed(mnemonic);


		$("#private-for-sign").val(wallet.keys.private.hex)

		var addressFrom = JSON.parse($("#tx").val()).value.msg[0].value.from_address

		if(wallet.address.bech32.string == addressFrom){
			$("#private-for-sign").change();
		}
	 })


	 $("#private-for-sign").on("keyup change",function(){
			var tx = JSON.parse($("#tx").val());

			tx = tx.value
			tx["account_number"] = $("#account-number").val()
			tx["sequence"] = $("#sequence").val()
			tx["chain_id"] = "spend";
			tx["msgs"] = tx["msg"];
			delete (tx.msg);
			tx = utils.abcSortJson(tx);
// 
			// console.log(JSON.stringify(tx))

			var privHex =$("#private-for-sign").val().trim().replace(/\s{2,}/g, ' ');
			var priv = spendCrypto.bufferFromHex(privHex)
			var signature = spendCrypto.signWithPrivateKey(tx ,priv ).signature.toString("base64") 

			 $("#signature").val(signature)
			 $("#signature-send").val(signature)

	 })


	 $("#send-transaction").on("click",function(){

		var tx = JSON.parse($("#tx").val());
		console.log(tx)
	
		var fromAddress = tx.value.msg[0].value.from_address
	
	
		// this can be configurable too
		var url = "http://18.185.105.50:9071/auth/accounts/"
	
		$.ajax({
		  dataType: "json",
		  url: url+fromAddress,
		  success: function(response){
				  $("#account-number").val(response.account.value.account_number)
				  $("#sequence").val(response.account.value.sequence)
		  }
		});
	
	})
	
})


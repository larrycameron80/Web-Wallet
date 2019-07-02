$(document).ready(function(){
	 // test()

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
			$("textarea#old-mnemonic").val("forward coconut salmon illegal now random select suit seminar click recall hen rhythm improve oven core utility rain enable energy fish lounge follow such")

			$("input#from-address").val("spend1d8lyh058z20g27y2z0gu29k8vnf57dvfq75rgr")
			$("input#to-address").val("spend159sfnmsar0zh0fk3974un9f5x6qkaqx5am9gew")
			$("input#amount").val(500)
			$("select#coin").val("stake")
			
		
			$("textarea#old-mnemonic").change()
			$("input#from-address").change()
			$("#generate-wallet").click()
			
			$("#tx").val( $("#new-tx").val()) 
			$("#request-info").click()

			$("#mnemonic-for-sign").val("forward coconut salmon illegal now random select suit seminar click recall hen rhythm improve oven core utility rain enable energy fish lounge follow such")
			$("#mnemonic-for-sign").change();
			$("#tx").change()
		})
	}


   $("#continue-tx").click(function(){

   	$("#tx").val($("#new-tx").val())
   	$(".section.send-spend a[href='#sign']").click()
   	$("#request-info").click()
   })

	$(".nav.navbar-nav a").click(function(){
		// console.log(123)
		$(".nav.navbar-nav li").removeClass("active")
		$(this).parent().addClass("active")
	   var section = $(".section."+$(this).attr("section"))
	   $("body > .section").hide()
	   section.show()

	})

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

   var signatureTemplate= {
     "pub_key": {
       "type": "tendermint/PubKeySecp256k1",
       "value": ""
     },
     "signature": ""
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
		  		$("#sequence").change()
		  }
		});

	})


	 $("#make-signature").on("click",function(){
	 // $("#mnemonic-for-sign").on("keyup change",function(){
		var mnemonic = $("#mnemonic-for-sign").val().trim().replace(/\s{2,}/g, ' ');
		var wallet = spendCrypto.getWalletFromSeed(mnemonic);


		$("#private-for-sign").val(wallet.keys.private.hex)

		var addressFrom = JSON.parse($("#tx").val()).value.msg[0].value.from_address

		// $("#private-for-sign").change();
		doSigning()

	 })
	 $("#tx").on("keyup change",function(){
		// $(" #private-for-sign").change()
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
			   // console.log(response);
			})
		})




	 function doSigning(){
	 // $(" #private-for-sign , #indent-signed , #account-number , #sequence").on("keyup change",function(){
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

		var fromAddress = tx["msgs"][0].value.from_address

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


	$("#broadcast").click(function(){

	});

	if(location.hash.substr(1)==""){
		window.location="#send-spend"
	}
	 $("a[section='"+location.hash.substr(1)+"']" ).click()
	 $("body").show()

})

vcl 4.0;

import dynamic;
import cookie;
import header;
import std;
import querystring;


backend default {
    .host = "localhost";
    .port = "8081";
}




sub vcl_init {
    new www_dir = dynamic.director(
                    port = "80",
                    ttl = 5m );

    #For dealing with query strings
    new whitelistQS = querystring.filter();
    whitelistQS.add_string("qty");
    whitelistQS.add_string("redirect_uri");
    whitelistQS.add_string("multi_value_attr");
    whitelistQS.add_string("a.product_size");
    whitelistQS.add_string("a.product-colour");
    whitelistQS.add_string("a.ink-colour");
    whitelistQS.add_string("variantid");
    whitelistQS.add_string("keyCode");
    whitelistQS.add_string("alternateKeyCode");
    whitelistQS.add_string("templatekey");
    whitelistQS.add_string("orderedcategory");
    whitelistQS.add_string("redirect_uri");
    whitelistQS.add_string("q");
    whitelistQS.add_string("orderId");
    whitelistQS.add_string("guid"); 
    whitelistQS.add_string("shipAndBill");
    whitelistQS.add_string("campaignKey");
    whitelistQS.add_string("variantSku"); 
    #Query string for order summary partial page
    whitelistQS.add_string("cartId");
    #Query string for facet serach
    whitelistQS.add_string("searchTerm");
    whitelistQS.add_string("action");
    whitelistQS.add_string("filterdata");
    whitelistQS.add_string("barrel_colour");
    whitelistQS.add_string("product_colour");
    whitelistQS.add_string("ink_colour");
    whitelistQS.add_string("material");
    whitelistQS.add_string("usb_size");
    whitelistQS.add_string("printing_method");
    whitelistQS.add_string("price_range");
    whitelistQS.add_string("price_desc");
    whitelistQS.add_string("best_seller_asc");
    whitelistQS.add_string("max");
    whitelistQS.add_string("min");
    whitelistQS.add_string("price_asc");
    whitelistQS.add_string("size");
    whitelistQS.add_string("sort");
    whitelistQS.add_string("page");
    whitelistQS.add_string("offset");
    #mini cart (locale also used in ABC-8048)
    whitelistQS.add_string("isLogged");
    whitelistQS.add_string("d");
    whitelistQS.add_string("locale");
    whitelistQS.add_string("anonymousId");
    whitelistQS.add_string("token");
    #Sign-up QS
    whitelistQS.add_string("id");
    #Used in my-account
    whitelistQS.add_string("msg");
    #Used in order-summary
    whitelistQS.add_string("couponToBeApplied");
    
    # ABC-7647, used on PCP
    whitelistQS.add_string("campaign");

    #ABC-8048 & ABC-8049
    whitelistQS.add_string("componentName");
    whitelistQS.add_string("forcedUpdate");
    
    #ABC-10304
    whitelistQS.add_string("a.taille_du_produit"); #FR
    whitelistQS.add_string("a.produktgr%C3%B6%C3%9Fe"); #DE Encoded
    whitelistQS.add_string("a.produktgröße"); #DE
    whitelistQS.add_string("a.taglia_del_prodotto"); #IT
    whitelistQS.add_string("a.product_grootte"); #NL
    whitelistQS.add_string("a.tamanho_do_produto"); #PT
    whitelistQS.add_string("a.tamaño_del_producto"); #ES
    whitelistQS.add_string("a.tama%C3%B1o_del_producto"); #ES Encoded
    
    #ABC-9870
    whitelistQS.add_string("code");
    whitelistQS.add_string("target");

    #ABC-10305
    whitelistQS.add_string("multi_ap");
}



sub vcl_recv {

    set req.backend_hint = www_dir.backend("{{BACKEND_HOST}}");

    # Let the module parse the "Cookie:" header from the client
    # cookie.parse(req.http.cookie);

    # Filter all except these cookies from it
    #cookie.filter_except("JSESSIONID,cookieConsent,np.anonymousId");

    # Set the "Cookie:" header to the parsed/filtered value, removing all unnecessary cookies
    #set req.http.cookie = cookie.get_string();

    #Handling ALB HealthCheck requests
    if (req.url == "/varnish-health" ){
        return(synth(200));
    }

    if (req.method == "BAN"  ) {
        if (req.http.X-API-KEY != "{{BAN_API_KEY}}" ){
            return(synth(403));
        }

               #BAN EXACT
        if ( req.http.X-BAN-TYPE && req.http.X-BAN-TYPE == "EXACT" ){
            ban("req.url == " + req.url );
            return(synth(201));
        }
        
        #BAN QS
        if ( req.http.X-BAN-TYPE && req.http.X-BAN-TYPE == "QUERY_STRING" ){
            ban( "req.url ~ " + req.url + "?"  );
            ban( "req.url ~ " + req.url + "/?"  );
            return(synth(201));
        }

        #BAN WILDCARDS
        if ( req.http.X-BAN-TYPE && req.http.X-BAN-TYPE == "PATTERN"){
            ban("req.url ~ " + req.url );
            return(synth(201));
        }
    return(synth(400));
    }

    if (req.method != "GET" && req.method != "HEAD" && req.method != "PUT" && req.method != "POST" && req.method != "TRACE" && req.method != "OPTIONS" && req.method != "DELETE" && req.method != "BAN" ) {
        return (pipe);
    }

    if (req.method != "GET" && req.method != "HEAD") {
      return (pass);  
    }
    
    if (req.http.cookie ~ "np.brandKeywordCampaign") {
        set req.http.X-Backup-Cookie = req.http.cookie;
        #using cookie-vmod to filter desired cookie with value
        cookie.parse(req.http.cookie);
        # filter everything but a few:
        cookie.filter_except("np.brandKeywordCampaign");
        # Store it back into req
        set req.http.cookie = cookie.get_string();
        #setting cookie value in a header
        set req.http.X-Brand-Campaign = req.http.cookie;
        
        # reset cookie value back to original place
        set req.http.cookie = req.http.X-Backup-Cookie;

        unset req.http.X-Backup-Cookie;
    }

    #whitelist query strings
    set req.url = whitelistQS.apply(req.url, keep);

return (hash);
}

sub vcl_hash {
    hash_data(req.url);

    if (req.http.cookie ~ "np.brandKeywordCampaign" && req.http.X-Brand-Campaign ~ "showWebProspectPricing~true") {
        hash_data("showWebProspectPricing");
    } 
    unset req.http.X-Brand-Campaign;
    if (req.http.host) {
         hash_data(req.http.host);
    } else {
        hash_data(server.ip);
    }
    return (lookup);
}


sub vcl_backend_response {
	if (bereq.url ~ "\.(jpe?g|png|gif|pdf|gz|tgz|bz2|tbz|tar|zip|tiff|tif)$" && beresp.http.Set-Cookie ) {
		unset beresp.http.Set-Cookie;
	}	

	if (beresp.http.cache-control ~ "max-age"){
        unset beresp.http.Set-Cookie;
		unset beresp.http.cache-control;
		set beresp.http.cache-control = "max-age=3600, public";
	}	
}

sub vcl_deliver {
    unset resp.http.X-Varnish;
    unset resp.http.Via;
    unset resp.http.Server;
    unset resp.http.X-Magnolia-Registration;

    if (obj.hits > 0) {
        set resp.http.X-Cache = "HIT";
    } else {
        set resp.http.X-Cache = "MISS";
    }
}
sub vcl_synth {
    set resp.http.Content-Type = "text/html; charset=utf-8";
    set resp.http.Retry-After = "5";
   
    if (resp.status == 200) {
        synthetic("Ok");
    }

	if (resp.status == 403) {
		synthetic("Access token missing");
	}	
   
	if (resp.status == 201) {
        synthetic("Ban addedd successfully");
    }

	if (resp.status == 400) {
        synthetic("Invalid/Incomplete data");
    }
    return (deliver);
}

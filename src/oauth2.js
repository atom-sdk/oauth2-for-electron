'use strict';
const {urlParams} = require('./utils');
const request = require('./request');

module.exports = function(config)
{
	const auth_url = config.auth_url;
	const token_url = config.token_url;
	const client_id = config.client_id;
	const client_secret = config.client_secret;
	const redirect_uri = config.redirect_uri;
	const state = config.state;
	const code_challenge = config.code_challenge;
	const code_verifier = config.code_verifier;
	const auth_query_params = config.auth_query_params;

	// Set scope deliminator.
	let scope_deliminator = " ";
	if(config.scope_deliminator)
	{
		scope_deliminator = config.scope_deliminator;
	}
	const scope = config.scope.join(scope_deliminator);

	const getToken = async (grant) =>
	{
		const redirectUri = grant.app_id && grant.workspace ? `${redirect_uri}?app_id=${grant.app_id}&workspace=${grant.workspace}` : grant.app_id ? `${redirect_uri}?app_id=${grant.app_id}` : redirect_uri;
		const clientId = grant.app_id || client_id;
		delete grant.app_id
		delete grant.workspace
		
		const params = {
			...grant,
			redirect_uri: redirectUri,
			client_id: clientId,
			client_secret,
			code_verifier,
		};

    	const request_config = {
			url: token_url,
			method: "POST",
			headers: {
				'Content-Type': 'application/x-www-form-urlencoded'
			},
			form: params,
			json: true
		};

        try
        {
        	const data = await request(request_config);
        	if(data.hasOwnProperty('access_token'))
			{
				return data;
			}
			else
			{
				let err = new Error('FAILED_TO_REFRESH_TOKEN');
				err.response = data;
				throw err;
			}
        }
        catch(err)
        {
        	throw err;
        }
	}

	this.begin = (win, callback) => 
	{
		// Remove menu from the BrowserWindow.
		win.setMenu(null);

		let authorize_url = `${auth_url}?response_type=code`;
		authorize_url += `&client_id=${client_id}`;
		authorize_url += `&scope=${encodeURIComponent(scope)}`;
		authorize_url += `&redirect_uri=${encodeURIComponent(redirect_uri)}`;
		if (auth_query_params)
		{
			for (const param in auth_query_params) 
			{
				authorize_url += `&${param}=${auth_query_params[param]}`
			}
		}
		if(state)
		{
			authorize_url += `&state=${state}`;
		}
		if (code_challenge) 
		{
			authorize_url += `&code_challenge=${encodeURIComponent(code_challenge)}`;
			authorize_url += `&code_challenge_method=S256`;
		}

		win.webContents.on('will-redirect', async (event, url, httpResponseCode, statusText) => 
		{

			if(url.startsWith(redirect_uri))
			{
				const params = urlParams(url);
				if(params.hasOwnProperty('code'))
				{
					try
					{
						const grant = {
							grant_type: "authorization_code",
        					code: params.code,
							app_id: params.app_id,
							workspace: params.workspace
						};

						const data = await getToken(grant);
						callback(null, data);
					}
					catch(err)
					{
						callback(err, null);
					}

					win.close();
				}
				else
				{
					const error = new Error('AUTH_FAILED');
					error.response = params;
					callback(error, null);
				}
			}
		});

		win.loadURL(authorize_url);
	}

	this.refreshToken = async (refresh_token) => 
	{
		const grant = {
        	grant_type: "refresh_token",
        	refresh_token
        };

        try
		{
			const data = await getToken(grant);
			return data;
		}
		catch(err)
		{
			throw err;
		}
	}
}

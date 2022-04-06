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
	
	// Set scope deliminator.
	let scope_deliminator = " ";
	if(config.scope_deliminator)
	{
		scope_deliminator = config.scope_deliminator;
	}
	const scope = config.scope.join(scope_deliminator);

	const getToken = async (grant) =>
	{
		const params = {
        	...grant,
        	redirect_uri,
			client_id,
        	client_secret
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
		if(state)
		{
			authorize_url += `&state=${state}`;
		}

		win.webContents.on('will-redirect', async (event, url, httpResponseCode, statusText) => 
		{
			if(url.startsWith(redirect_uri))
			{
				
				event.preventDefault();
				const params = urlParams(url);
				if(params.hasOwnProperty('code'))
				{
					try
					{
						const grant = {
							grant_type: "authorization_code",
        					code: params.code
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

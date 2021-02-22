def headers(jwt, type_='Bearer'):
    return {'Authorization': f'{type_} {jwt}'}

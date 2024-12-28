import os
import logging
import urllib3
from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search, Q
from dotenv import load_dotenv
import polars as pl

class ElasticQuery:
    def __init__(self, host: str = "security-onion-server", port: int = 9200, log_level=logging.INFO):
        self.logger = logging.getLogger("ElasticQuery")
        self.logger.setLevel(log_level)
        if not self.logger.hasHandlers():
            formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
            handler = logging.StreamHandler()
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

        current_dir = os.path.dirname(os.path.abspath(__file__))    
        dotenv_path = os.path.join(current_dir, '.env')
        load_dotenv(dotenv_path)
        load_dotenv()
        api_key = os.getenv("ELASTIC_API_KEY")
        if not api_key:
            raise ValueError("ELASTIC_API_KEY not found in environment variables.")

        self.logger.debug(host)
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self.client = Elasticsearch(
            [f"https://{host}:{port}"],
            api_key=api_key,
            verify_certs=False  # Disable TLS verification
        )

        self.logger.debug(self.client.info())
        
        self.fields = [
            "host.name", "host.os.family", "process.command_line", "process.parent.command_line",
            "process.executable", "process.parent.executable", "process.parent.name", "process.pid", "process.parent.pid",
            "process.entity_id", "process.Ext.ancestry", "source.ip", "source.port",
            "destination.ip", "destination.port", "network.protocol", "@timestamp", "process.group_leader.pid",
            "user.name", "user.department", "user.title", "user.city", "user.state", "process.session_leader.pid"
        ]

    def search(self, query: Q, index: str = "logs-*", start_date: str = "", end_date: str = "", 
               scroll: str = "10m", batch_size: int = 3000) -> pl.DataFrame:
        """
        Execute a search query with optional date range filtering and return results as a Polars DataFrame.

        Args:
            index (str): The index to query.
            query (dict): The query DSL.
            start_date (str): Start date for filtering (format: YYYY-MM-DDTHH:MM:SSZ).
            end_date (str): End date for filtering (format: YYYY-MM-DDTHH:MM:SSZ).
            scroll (str): Scroll time to keep the search context alive.
            batch_size (int): Number of hits to retrieve per batch.

        Returns:
            pl.DataFrame: A Polars DataFrame containing the filtered results.
        """
        def flatten_dict(d, parent_key='', sep='.'):
            items = []
            for k, v in d.items():
                new_key = f"{parent_key}{sep}{k}" if parent_key else k
                if isinstance(v, dict):
                    items.extend(flatten_dict(v, new_key, sep=sep).items())
                else:
                    items.append((new_key, v))
            return dict(items)

        # Add date filtering to the query
        if start_date or end_date:
            date_range_query = Q('range', **{'@timestamp': {'gte': start_date, 'lt': end_date}})
            query = query & date_range_query

        # Execute the initial search with scroll
        search = Search(using=self.client, index=index).query(query).source(self.fields).extra(size=batch_size)
        response = search.params(scroll=scroll).execute()

        # Process results incrementally
        results = []
        for hit in response.hits.hits:
            results.append(hit["_source"])

        scroll_id = response['_scroll_id']

        while True:
            response = self.client.scroll(scroll_id=scroll_id, scroll=scroll)
            if not response['hits']['hits']:
                break
            for hit in response['hits']['hits']:
                results.append(hit["_source"])

        # Clear the scroll context
        self.client.clear_scroll(scroll_id=scroll_id)
        
        return pl.DataFrame([flatten_dict(record) for record in results])
    
    def close(self):
        """
        Close the Elasticsearch client connection.
        """
        self.client.close()


if __name__ == "__main__":
    host = "security-onion-server"  
    port = 9200
    index = "logs-*" 
    query = {
        "query": {
            "match_all": {}
        }
    }
    start_date = "2024-12-01T00:00:00Z"
    end_date = "2024-12-15T23:59:59Z"


    elastic_query = ElasticQuery(host, port)

    try:
        # Execute a query and retrieve the results
        df = elastic_query.search(index=index, query=query, start_date=start_date, end_date=end_date)
        print(df.head())  # Display the first few rows
    finally:
        # Ensure the client connection is closed
        elastic_query.close()
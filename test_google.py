import os
import requests

API_KEY ="AIzaSyDWRKgMbkn4G4imT7R5SjJlsUQUegfMQZ4"
CX = "e4fb3a57eba014f07"

def google_search(query, num_results=5):
    """Perform Google search using Custom Search API"""
    url = "https://www.googleapis.com/customsearch/v1"
    params = {
        'q': query,
        'key': API_KEY,
        'cx': CX,
        'num': num_results
    }
    
    try:
        response = requests.get(url, params=params)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error during API request: {e}")
        return None

def process_results(search_results):
    """Extract and structure search results"""
    if not search_results or 'items' not in search_results:
        print("No results found")
        return None
    
    processed = []
    for item in search_results['items']:
        result = {
            'title': item.get('title'),
            'link': item.get('link'),
            'snippet': item.get('snippet'),
            'highlights': []
        }
        
        # Extract key highlights (simplified example)
        snippet = item.get('snippet', '')
        if ' - ' in snippet:
            result['highlights'] = [part.strip() for part in snippet.split(' - ') if part.strip()]
        
        processed.append(result)
    
    return processed

def generate_summary(results):
    """Generate consolidated summary from results"""
    if not results:
        return "No summary available"
    
    snippets = [result['snippet'] for result in results if result['snippet']]
    combined_text = ' '.join(snippets)
    
    # Simple summarization (in real usage, consider NLP libraries)
    key_points = set()
    for snippet in snippets:
        if len(snippet := snippet.strip()) > 0:
            if snippet.endswith('.'): 
                snippet = snippet[:-1]
            key_points.add(snippet.split('. ')[0])
    
    return {
        'total_results': len(results),
        'summary': ' '.join(combined_text[:250].split(' ')[:-1]) + '...' if combined_text else '',
        'key_points': list(key_points)[:5]  # Top 5 unique points
    }

def main():
    query = input("Enter your search query: ")
    print(f"\nSearching for: '{query}'...\n")
    
    # Perform search
    results = google_search(query)
    if not results:
        return
    
    # Process results
    processed = process_results(results)
    if not processed:
        return
    
    # Generate summary
    summary = generate_summary(processed)
    
    # Display summary
    print(f"📝 SUMMARY ({summary['total_results']} results analyzed)")
    print(summary['summary'])
    print("\n🔑 KEY POINTS:")
    for i, point in enumerate(summary['key_points'], 1):
        print(f"{i}. {point}")
    
    # Display detailed results
    print("\n🌐 TOP RESULTS:")
    for i, result in enumerate(processed, 1):
        print(f"\n{i}. {result['title']}")
        print(f"   🔗 {result['link']}")
        print(f"   📄 {result['snippet']}")
        if result['highlights']:
            print("   💡 HIGHLIGHTS:")
            for hl in result['highlights']:
                print(f"      - {hl}")

if __name__ == "__main__":
    main()
